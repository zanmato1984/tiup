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

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticServerPrivateFiles(t *testing.T) {
	for _, keyLocation := range []string{"default", "custom", "external", "symlink-root"} {
		t.Run(keyLocation, func(t *testing.T) {
			root := t.TempDir()
			if keyLocation == "symlink-root" {
				alias := filepath.Join(t.TempDir(), "mirror")
				require.NoError(t, os.Symlink(root, alias))
				root = alias
			}
			keyDir := filepath.Join(root, "keys")
			switch keyLocation {
			case "custom":
				keyDir = filepath.Join(root, "private-signing")
			case "external":
				keyDir = t.TempDir()
			}
			require.NoError(t, os.MkdirAll(keyDir, 0700))
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				_, _ = w.Write([]byte("upstream public file"))
			}))
			defer upstream.Close()
			configuredKeyDir := keyDir
			if keyLocation == "default" || keyLocation == "symlink-root" {
				configuredKeyDir = ""
			}
			s, err := newServer(root, configuredKeyDir, upstream.URL)
			require.NoError(t, err)
			// Use inert markers, not signing keys or executable packages.
			require.NoError(t, os.WriteFile(filepath.Join(keyDir, "private.json"), []byte("PRIVATE TEST MARKER"), 0600))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "keys"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "keys", "legacy.json"), []byte("LEGACY PRIVATE MARKER"), 0600))
			require.NoError(t, os.WriteFile(filepath.Join(root, "root.json"), []byte("public metadata"), 0600))
			require.NoError(t, os.Mkdir(filepath.Join(root, "public"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "public", "component.tar.gz"), []byte("public archive"), 0600))
			require.NoError(t, os.Symlink(filepath.Join(keyDir, "private.json"), filepath.Join(root, "key-alias.json")))
			require.NoError(t, os.Symlink(keyDir, filepath.Join(root, "key-alias-dir")))
			require.NoError(t, os.Symlink(filepath.Join("keys", "legacy.json"), filepath.Join(root, "relative-key")))
			external := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(external, "other.json"), []byte("OUTSIDE ROOT MARKER"), 0600))
			require.NoError(t, os.Symlink(filepath.Join(external, "other.json"), filepath.Join(root, "outside-alias.json")))
			h := s.router()
			blocked := []string{"/keys", "/keys/", "/keys/legacy.json", "/keys/missing.json", "/KEYS/legacy.json", "/KEYS/missing.json", "/%6beys/legacy.json", "/key-alias.json", "/key-alias-dir/private.json", "/key-alias-dir/missing.json", "/relative-key", "/outside-alias.json", "/", "/public/"}
			if keyLocation == "custom" {
				blocked = append(blocked, "/private-signing/private.json", "/private-signing/missing.json", "/PRIVATE-SIGNING/missing.json")
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, target := range blocked {
					t.Run(method+target, func(t *testing.T) {
						w := httptest.NewRecorder()
						h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
						require.Equal(t, http.StatusForbidden, w.Code)
						require.NotContains(t, w.Body.String(), "MARKER")
						require.Zero(t, upstreamRequests.Load(), "private paths must not reach the upstream")
					})
				}
			}
			for target, body := range map[string]string{"/root.json": "public metadata", "/public/component.tar.gz": "public archive", "/missing-public.json": "upstream public file"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, body, w.Body.String())
			}
			require.Equal(t, int32(1), upstreamRequests.Load())
		})
	}
}

func TestStaticServerKeyDirectoryAliases(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "signing"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "signing", "private.json"), []byte("PRIVATE MARKER"), 0600))
	alias := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.Symlink(filepath.Join(root, "signing"), alias))
	for _, keyDir := range []string{alias, filepath.Join(root, "public", "..", "signing"), root} {
		h := staticServer(root, "", keyDir)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/signing/private.json", nil))
		require.Equal(t, http.StatusForbidden, w.Code, keyDir)
		require.NotContains(t, w.Body.String(), "MARKER")
	}
}

func TestStaticServerPublicHTTP(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "keys-public"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "keys-public", "package.tar.gz"), []byte("public archive"), 0600))
	require.NoError(t, os.Symlink(filepath.Join(root, "keys-public", "package.tar.gz"), filepath.Join(root, "public-link")))
	h := staticServer(root, "")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/keys-public/package.tar.gz", nil))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "14", w.Header().Get("Content-Length"))
		if method == http.MethodGet {
			require.Equal(t, "public archive", w.Body.String())
		} else {
			require.Empty(t, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/keys-public/package.tar.gz", nil)
	r.Header.Set("Range", "bytes=0-5")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusPartialContent, w.Code)
	require.Equal(t, "public", w.Body.String())
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/public-link", nil))
	require.Equal(t, http.StatusForbidden, w.Code, "public symlinks are deliberately unsupported")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/missing.json", nil))
	require.Equal(t, http.StatusNotFound, w.Code)
}

// This stress test supplements the handle-identity checks; passing a stress
// test (or Go's race detector) alone does not prove filesystem race safety.
func TestStaticServerPathReplacement(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(root, "keys"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "keys", "file"), []byte("PRIVATE MARKER"), 0600))
			public := filepath.Join(root, "public")
			private := filepath.Join("keys", "file")
			target := "/public"
			if directory {
				require.NoError(t, os.Mkdir(public, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(public, "file"), []byte("public file"), 0600))
				private = "keys"
				target += "/file"
			} else {
				require.NoError(t, os.WriteFile(public, []byte("public file"), 0600))
			}
			stop := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				for {
					select {
					case <-stop:
						done <- nil
						return
					default:
					}
					for _, change := range []func() error{
						func() error { return os.Rename(public, public+"-saved") },
						func() error { return os.Symlink(private, public) },
						func() error { runtime.Gosched(); return os.Remove(public) },
						func() error { return os.Rename(public+"-saved", public) },
					} {
						if err := change(); err != nil {
							done <- err
							return
						}
					}
				}
			}()
			defer func() {
				close(stop)
				require.NoError(t, <-done)
			}()
			h := staticServer(root, "")
			for range 1000 {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
				require.NotContains(t, w.Body.String(), "PRIVATE MARKER")
				if w.Code == http.StatusOK {
					require.Equal(t, "public file", w.Body.String())
				}
			}
		})
	}
}

func TestStaticServerMissingPrivateDirectories(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "mirror")
	require.NoError(t, os.Symlink(root, alias))
	for _, root := range []string{root, alias} {
		for _, keyDir := range []string{"", filepath.Join(root, "private-signing")} {
			s, err := newServer(root, keyDir, "://invalid-upstream")
			require.NoError(t, err)
			for _, target := range []string{"/keys/missing.json", "/KEYS/missing.json", "/private-signing/missing.json"} {
				if keyDir == "" && target == "/private-signing/missing.json" {
					continue
				}
				w := httptest.NewRecorder()
				s.router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
				require.Equal(t, http.StatusForbidden, w.Code)
			}
		}
	}
}
