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

// Package keydir defines the private signing-key layout shared by mirror tools.
package keydir

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns an absolute private directory separate from the public mirror.
// The default is a sibling named <mirror>.keys, never a child of the mirror.
func Resolve(mirror, configured string) (string, error) {
	root, err := canonical(mirror)
	if err != nil {
		return "", err
	}
	if configured == "" {
		if filepath.Dir(root) == root {
			return "", fmt.Errorf("a filesystem root cannot be used as a public mirror")
		}
		configured = root + ".keys"
	}
	private, err := canonical(configured)
	if err != nil {
		return "", err
	}
	// Reserve case aliases too: deployment and upstream filesystems can differ.
	for _, pair := range [][2]string{{root, private}, {private, root}} {
		rel, err := filepath.Rel(strings.ToLower(pair[0]), strings.ToLower(pair[1]))
		overlap := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
		// Lexical checks alone miss aliases such as APFS Unicode normalization.
		// Compare existing ancestor identities even when the final child is new.
		base, err := os.Stat(pair[0])
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if err == nil {
			for ancestor := pair[1]; ; ancestor = filepath.Dir(ancestor) {
				info, err := os.Stat(ancestor)
				if err == nil && os.SameFile(base, info) {
					overlap = true
					break
				}
				if err != nil && !os.IsNotExist(err) {
					return "", err
				}
				if filepath.Dir(ancestor) == ancestor {
					break
				}
			}
		}
		if overlap {
			return "", fmt.Errorf("private key directory %q must be outside, and must not contain, public mirror %q", private, root)
		}
	}
	return private, nil
}

// canonical resolves existing ancestors as well as not-yet-created directories.
// An existing dangling link is an error, not a reason to discard its target.
func canonical(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	if _, err = os.Lstat(abs); err == nil {
		return filepath.EvalSymlinks(abs)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	resolved, err := canonical(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(abs)), nil
}

// CheckLegacy refuses legacy in-root keys instead of silently ignoring them.
func CheckLegacy(mirror string) error {
	entries, err := os.ReadDir(mirror)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), "keys") {
			return fmt.Errorf("legacy signing-key path %q is inside the public mirror; stop publishing and run `tiup mirror migrate-keys <mirror-dir> --from <legacy-key-dir>` before continuing", filepath.Join(mirror, entry.Name()))
		}
	}
	return nil
}

// CheckPermissions requires an owner-only directory. It never changes existing
// permissions; migration is the explicit operation that tightens legacy keys.
func CheckPermissions(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key directory %q must be a real directory with owner-only permissions (0700)", dir)
	}
	return nil
}

// Create reserves a new owner-only key directory. Existing directories are not
// reused: init/clone must not silently replace an existing signing identity.
func Create(mirror, configured string) (string, error) {
	dir, err := Resolve(mirror, configured)
	if err != nil {
		return "", err
	}
	if err := CheckLegacy(mirror); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", fmt.Errorf("create new private key directory %q (it must not already exist): %w", dir, err)
	}
	return dir, nil
}
