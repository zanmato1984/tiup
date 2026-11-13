// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repository

import (
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiup/pkg/repository/keydir"
	"github.com/pingcap/tiup/pkg/repository/v1manifest"
	"github.com/stretchr/testify/require"
)

func TestMirrorInitPublicOnlyAndSigning(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "custom"}[custom], func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "mirror")
			require.NoError(t, os.Mkdir(root, 0755))
			configured := ""
			if custom {
				configured = filepath.Join(t.TempDir(), "private")
			}
			require.NoError(t, v1manifest.Init(root, configured, time.Now().UTC()))
			assertPublicMirror(t, root)
			m := NewMirror(root, MirrorOptions{KeyDir: configured}).(*localFilesystem)
			require.NoError(t, m.Open())
			require.NotEmpty(t, m.keys)
			assertPrivatePermissions(t, m.keyDir)
			// Grant signs new index, snapshot and timestamp with the discovered keys.
			for _, key := range m.keys {
				public, err := key.Public()
				require.NoError(t, err)
				require.NoError(t, m.Grant("new-owner", "New Owner", public))
				break
			}
		})
	}
}

func TestMirrorInitRejectsInRootKeys(t *testing.T) {
	root := t.TempDir()
	require.ErrorContains(t, v1manifest.Init(root, filepath.Join(root, "keys"), time.Now()), "must be outside")
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestClonePublicOnlyAndNoIdentityReplacement(t *testing.T) {
	repo := NewV1Repo(&MockMirror{Resources: map[string]string{}}, Options{}, v1manifest.NewMockManifests())
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "custom"}[custom], func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "clone")
			options := CloneOptions{OSs: []string{"linux"}, Archs: []string{"amd64"}}
			if custom {
				options.KeyDir = filepath.Join(t.TempDir(), "private")
			}
			require.NoError(t, CloneMirror(repo, nil, root, nil, options))
			assertPublicMirror(t, root)
			m := NewMirror(root, MirrorOptions{KeyDir: options.KeyDir}).(*localFilesystem)
			require.NoError(t, m.Open())
			require.NotEmpty(t, m.keys)
			assertPrivatePermissions(t, m.keyDir)
			before, err := readMigrationKeys(m.keyDir)
			require.NoError(t, err)
			require.ErrorContains(t, CloneMirror(repo, nil, root, nil, options), "must be empty")
			after, err := readMigrationKeys(m.keyDir)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
	root := filepath.Join(t.TempDir(), "bad-clone")
	err := CloneMirror(repo, nil, root, nil, CloneOptions{OSs: []string{"linux"}, Archs: []string{"amd64"}, KeyDir: filepath.Join(root, "keys")})
	require.ErrorContains(t, err, "must be outside")
}

func TestMigrateKeysPreservesIdentityAndPublicMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mirror")
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, v1manifest.Init(root, "", time.Now().UTC()))
	private, err := keydir.Resolve(root, "")
	require.NoError(t, err)
	before, err := readMigrationKeys(private)
	require.NoError(t, err)
	publicBefore := publicHashes(t, root)
	legacy := filepath.Join(root, "keys")
	require.NoError(t, os.Rename(private, legacy))
	require.NoError(t, filepath.WalkDir(legacy, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(name, 0755)
		}
		return os.Chmod(name, 0644)
	}))
	m := NewMirror(root, MirrorOptions{}).(*localFilesystem)
	require.ErrorContains(t, m.Open(), "migrate-keys")
	destination, err := MigrateKeys(root, "", "")
	require.NoError(t, err)
	require.Equal(t, private, destination)
	after, err := readMigrationKeys(filepath.Join(destination, "keys"))
	require.NoError(t, err)
	require.Equal(t, before, after, "migration preserves the exact private-key bytes")
	require.Equal(t, publicBefore, publicHashes(t, root), "migration must not re-sign public metadata")
	require.NoDirExists(t, legacy)
	assertPrivatePermissions(t, destination)
	require.NoError(t, m.Open())
	for _, key := range m.keys {
		public, err := key.Public()
		require.NoError(t, err)
		require.NoError(t, m.Grant("after-migration", "After migration", public))
		break
	}
	assertPublicMirror(t, root)
}

func TestMigrateKeysRejectsUnsafeInputsWithoutRemovingSource(t *testing.T) {
	key, err := v1manifest.GenKeyInfo()
	require.NoError(t, err)
	content, err := json.Marshal(key)
	require.NoError(t, err)
	for _, scenario := range []string{"existing-target", "inside-target", "symlink", "invalid-file", "custom-source"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "keys")
			require.NoError(t, os.Mkdir(source, 0700))
			keyPath := filepath.Join(source, "old.json")
			require.NoError(t, os.WriteFile(keyPath, content, 0600))
			destination := filepath.Join(t.TempDir(), "private")
			switch scenario {
			case "existing-target":
				require.NoError(t, os.Mkdir(destination, 0700))
			case "inside-target":
				destination = filepath.Join(root, "new-keys")
			case "symlink":
				require.NoError(t, os.Symlink(keyPath, filepath.Join(source, "alias.json")))
			case "invalid-file":
				require.NoError(t, os.WriteFile(filepath.Join(source, "backup.txt"), []byte("unknown content"), 0600))
			case "custom-source":
				custom := filepath.Join(root, "old-signing")
				require.NoError(t, os.Rename(source, custom))
				_, err := MigrateKeys(root, custom, destination)
				require.NoError(t, err)
				require.NoDirExists(t, custom)
				assertPrivatePermissions(t, destination)
				return
			}
			_, err := MigrateKeys(root, "", destination)
			require.Error(t, err)
			require.FileExists(t, keyPath)
			remaining, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			require.Equal(t, sha256.Sum256(content), sha256.Sum256(remaining))
		})
	}
}

func assertPublicMirror(t *testing.T, root string) {
	t.Helper()
	require.NoDirExists(t, filepath.Join(root, "keys"))
	require.NoError(t, filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(name)
		if err == nil {
			require.NotContains(t, string(content), `"private"`, "public-only tree must be safe to archive or serve")
		}
		return err
	}))
	h := http.FileServer(http.Dir(root)) // Not TiUP's filtered handler.
	for _, target := range []string{"/keys/index.json", "/keys/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		require.Equal(t, http.StatusNotFound, w.Code)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/root.json", nil))
	require.Equal(t, http.StatusOK, w.Code)
}

func assertPrivatePermissions(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		expected := os.FileMode(0600)
		if entry.IsDir() {
			expected = 0700
		}
		require.Equal(t, expected, info.Mode().Perm(), name)
		return nil
	}))
}

func publicHashes(t *testing.T, root string) map[string][sha256.Size]byte {
	t.Helper()
	hashes := make(map[string][sha256.Size]byte)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, entry.IsDir())
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		require.NoError(t, err)
		hashes[entry.Name()] = sha256.Sum256(content)
	}
	return hashes
}
