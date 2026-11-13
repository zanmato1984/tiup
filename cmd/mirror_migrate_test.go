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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiup/pkg/repository/keydir"
	"github.com/pingcap/tiup/pkg/repository/v1manifest"
	"github.com/stretchr/testify/require"
)

func TestMirrorMigrationCommand(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mirror")
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, v1manifest.Init(root, "", time.Now().UTC()))
	private, err := keydir.Resolve(root, "")
	require.NoError(t, err)
	require.NoError(t, os.Rename(private, filepath.Join(root, "keys")))
	var output bytes.Buffer
	cmd := newMirrorCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"migrate-keys", root})
	require.NoError(t, cmd.Execute())
	require.Contains(t, output.String(), "Private keys migrated")
	require.NoDirExists(t, filepath.Join(root, "keys"))
	require.DirExists(t, filepath.Join(private, "keys"))
	for _, command := range []string{"publish", "grant", "modify", "renew", "rotate", "clone"} {
		child, _, err := newMirrorCmd().Find([]string{command})
		require.NoError(t, err)
		require.True(t, child.Flags().Lookup("key-dir") != nil || child.InheritedFlags().Lookup("key-dir") != nil, command)
	}
}
