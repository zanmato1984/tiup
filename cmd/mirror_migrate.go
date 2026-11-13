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
	"fmt"

	"github.com/pingcap/tiup/pkg/repository"
	"github.com/spf13/cobra"
)

func newMirrorMigrateKeysCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "migrate-keys <mirror-dir>",
		Short: "Move legacy signing keys outside a public mirror without changing identity",
		Long: `Stop all HTTP/CDN publishing and signing processes before migration.
Move the old key directory into a new owner-only private container on the same
filesystem. The default source is <mirror>/keys and destination is <mirror>.keys.
The destination must not exist. No keys are regenerated and no metadata is changed.
Migration does not revoke keys previously exposed over HTTP.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			destination, err := cmd.Flags().GetString("key-dir")
			if err != nil {
				return err
			}
			destination, err = repository.MigrateKeys(args[0], source, destination)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Private keys migrated to %s; publish only %s. Update custom --key-dir settings before restarting signers. Previously exposed keys still require revocation/rotation.\n", destination, args[0])
			return err
		},
	}
	cmd.Flags().StringVar(&source, "from", "", "Existing key directory (default: <mirror>/keys); symlinks are refused")
	return cmd
}
