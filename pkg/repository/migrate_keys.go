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
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"

	"github.com/pingcap/tiup/pkg/repository/keydir"
	"github.com/pingcap/tiup/pkg/repository/v1manifest"
)

// MigrateKeys explicitly moves existing signing material out of a public mirror.
// Stop all publishers and signers first. No metadata is re-signed and no keys are
// regenerated. The directory move must be atomic (same filesystem); there is no
// copy/delete fallback that could lose a key or leave public copies behind.
func MigrateKeys(mirror, source, destination string) (string, error) {
	if source == "" {
		source = filepath.Join(mirror, "keys")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("migration source %q must be a real directory, not a symlink", source)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return "", err
	}
	destination, err = keydir.Resolve(mirror, destination)
	if err != nil {
		return "", err
	}
	if _, err := keydir.Resolve(source, destination); err != nil {
		return "", fmt.Errorf("migration source and destination must be separate: %w", err)
	}
	before, err := readMigrationKeys(source)
	if err != nil {
		return "", err
	}
	if len(before) == 0 {
		return "", fmt.Errorf("migration source %q contains no signing keys", source)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return "", err
	}
	// Reserve a fresh private container without overwriting an existing path.
	// Move the whole old tree into it; recursive loading preserves old filenames
	// and custom subdirectories without merging or replacing key files.
	if err := os.Mkdir(destination, 0700); err != nil {
		return "", fmt.Errorf("migration destination %q must not already exist: %w", destination, err)
	}
	moved := filepath.Join(destination, "keys")
	if err := os.Rename(source, moved); err != nil {
		_ = os.Remove(destination) // Only our newly-created, still-empty container.
		return "", fmt.Errorf("atomic key migration failed; source is unchanged (use the same filesystem): %w", err)
	}
	// On any subsequent error keep the material private, not back under HTTP.
	err = filepath.WalkDir(moved, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if entry.IsDir() {
			mode = 0700
		} else if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular entry in migrated keys: %q", name)
		}
		return os.Chmod(name, mode)
	})
	if err == nil {
		var after map[string][sha256.Size]byte
		after, err = readMigrationKeys(moved)
		if err == nil && !maps.Equal(before, after) {
			err = fmt.Errorf("key files changed during migration")
		}
	}
	if err != nil {
		return destination, fmt.Errorf("migration verification failed; keys are retained privately at %q, do not restore public access: %w", moved, err)
	}
	return destination, nil
}

func readMigrationKeys(dir string) (map[string][sha256.Size]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	hashes := make(map[string][sha256.Size]byte)
	err = filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("key migration refuses symlinks and special files: %q", name)
		}
		relative, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		f, err := root.Open(relative)
		if err != nil {
			return err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
			return fmt.Errorf("key file changed during validation: %q", name)
		}
		content, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return err
		}
		if len(content) > 1<<20 {
			return fmt.Errorf("key file exceeds 1 MiB: %q", name)
		}
		var key v1manifest.KeyInfo
		if err := json.Unmarshal(content, &key); err != nil || !key.IsPrivate() {
			return fmt.Errorf("migration source contains an invalid private key: %q", name)
		}
		if _, err := key.ID(); err != nil {
			return fmt.Errorf("migration source contains an unusable private key: %q", name)
		}
		hashes[relative] = sha256.Sum256(content)
		return nil
	})
	return hashes, err
}
