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

package keydir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolvePrivateLayout(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "mirror")
	require.NoError(t, os.Mkdir(root, 0755))
	canonicalRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	resolved, err := Resolve(root, "")
	require.NoError(t, err)
	require.Equal(t, canonicalRoot+".keys", resolved)
	alias := filepath.Join(parent, "alias")
	require.NoError(t, os.Symlink(root, alias))
	throughAlias, err := Resolve(alias, "")
	require.NoError(t, err)
	require.Equal(t, resolved, throughAlias)
	link := filepath.Join(parent, "link")
	require.NoError(t, os.Symlink(root, link))
	for _, private := range []string{root, filepath.Join(root, "keys"), filepath.Join(root, "missing", "keys"), parent, filepath.Join(link, "not-created", "keys")} {
		t.Run(private, func(t *testing.T) {
			_, err := Resolve(root, private)
			require.ErrorContains(t, err, "must be outside")
		})
	}
	dangling := filepath.Join(parent, "dangling")
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), dangling))
	_, err = Resolve(root, dangling)
	require.Error(t, err)
}

func TestCreateDoesNotReuseKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mirror")
	require.NoError(t, os.Mkdir(root, 0755))
	dir, err := Create(root, "")
	require.NoError(t, err)
	require.NoError(t, CheckPermissions(dir))
	_, err = Create(root, "")
	require.ErrorContains(t, err, "must not already exist")
	require.NoError(t, os.Chmod(dir, 0755))
	require.ErrorContains(t, CheckPermissions(dir), "0700")
	require.NoError(t, os.Mkdir(filepath.Join(root, "KEYS"), 0700))
	require.ErrorContains(t, CheckLegacy(root), "migrate-keys")
	_, err = Create(root, filepath.Join(t.TempDir(), "new-private"))
	require.ErrorContains(t, err, "migrate-keys")
}

func TestResolveFilesystemSpellingAliases(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "caf\u00e9")
	alias := filepath.Join(parent, "cafe\u0301")
	require.NoError(t, os.Mkdir(root, 0755))
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("filesystem does not alias Unicode normalization forms")
	}
	_, err := Resolve(root, filepath.Join(alias, "not-created", "keys"))
	require.ErrorContains(t, err, "must be outside")
}
