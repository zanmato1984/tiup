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

package v1manifest

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSavePrivateKeyCreationAndNoOverwrite(t *testing.T) {
	key, err := GenKeyInfo()
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "private")
	name, err := SaveKeyInfo(key, "test", dir)
	require.NoError(t, err)
	info, err := os.Stat(name)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	info, err = os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	before, err := os.ReadFile(name)
	require.NoError(t, err)
	_, err = SaveKeyInfo(key, "test", dir)
	require.ErrorIs(t, err, os.ErrExist)
	after, err := os.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(before), sha256.Sum256(after))
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("public sentinel"), 0644))
	aliasDir := t.TempDir()
	require.NoError(t, os.Symlink(sentinel, filepath.Join(aliasDir, filepath.Base(name))))
	_, err = SaveKeyInfo(key, "test", aliasDir)
	require.ErrorIs(t, err, os.ErrExist)
	untouched, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "public sentinel", string(untouched))
	_, err = SaveKeyInfo(key, "../escape", dir)
	require.ErrorContains(t, err, "must not contain a directory")
}
