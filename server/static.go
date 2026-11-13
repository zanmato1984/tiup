// Copyright 2020 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	logprinter "github.com/pingcap/tiup/pkg/logger/printer"
)

// mirrorFileSystem excludes signing-key directories, symlinks and directory listings.
type mirrorFileSystem struct {
	root        string
	privateDirs []string
}

func (fs mirrorFileSystem) Open(name string) (http.File, error) {
	local, err := filepath.Abs(fs.root)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(local)
	if err != nil {
		return nil, err
	}
	relative := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+name), "/"))
	if relative == "" {
		return nil, os.ErrPermission
	}
	file := filepath.Join(root, relative)
	var privateInfos []os.FileInfo
	for _, privateDir := range append([]string{filepath.Join(root, "keys")}, fs.privateDirs...) {
		private, err := filepath.Abs(privateDir)
		if err != nil {
			return nil, err
		}
		if pathWithin(local, private) {
			relative, err := filepath.Rel(local, private)
			if err != nil {
				return nil, err
			}
			private = filepath.Join(root, relative)
		}
		if pathWithin(private, file) {
			return nil, os.ErrPermission
		}
		resolved, err := filepath.EvalSymlinks(private)
		if err == nil && pathWithin(resolved, file) {
			return nil, os.ErrPermission
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		info, err := os.Stat(private)
		if err == nil {
			privateInfos = append(privateInfos, info)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	current, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = current.Close() }()
	parts := strings.Split(relative, string(filepath.Separator))
	for i, part := range parts {
		info, err := current.Lstat(part)
		if err != nil {
			return nil, err
		}
		last := i == len(parts)-1
		if (last && !info.Mode().IsRegular()) || (!last && !info.IsDir()) {
			return nil, os.ErrPermission
		}
		// Identity checks also cover filesystem-specific spelling aliases,
		// such as Unicode normalization, that lexical checks cannot recognize.
		for _, privateInfo := range privateInfos {
			if os.SameFile(privateInfo, info) {
				return nil, os.ErrPermission
			}
		}
		// Pin each directory before descending, then verify that the opened
		// object is the one we checked. Lstat followed by a single OpenInRoot
		// is insufficient: an in-root symlink to keys can replace a checked
		// public path between those calls. Never read from an unchecked handle.
		if last {
			f, err := current.Open(part)
			if err != nil {
				return nil, os.ErrPermission
			}
			opened, err := f.Stat()
			if err != nil || !os.SameFile(info, opened) {
				_ = f.Close()
				return nil, os.ErrPermission
			}
			return f, nil
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			return nil, os.ErrPermission
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			return nil, os.ErrPermission
		}
		_ = current.Close()
		current = next
	}
	return nil, os.ErrPermission
}

func pathWithin(dir, file string) bool {
	// Deny case variants even when the local private directory is absent:
	// a case-insensitive local or upstream filesystem may resolve them to keys.
	relative, err := filepath.Rel(strings.ToLower(dir), strings.ToLower(file))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// staticServer starts a static web server.
func staticServer(local string, upstream string, privateDirs ...string) http.Handler {
	fs := mirrorFileSystem{root: local, privateDirs: privateDirs}
	fsh := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, err := fs.Open(path.Clean(r.URL.Path)); err == nil {
			f.Close()
		} else if os.IsNotExist(err) && upstream != "" {
			if err := proxyUpstream(w, r, path.Join(local, path.Clean(r.URL.Path)), upstream); err != nil {
				logprinter.Errorf("Proxy upstream: %s", err.Error())
				fsh.ServeHTTP(w, r)
			}
			logprinter.Errorf("Handle file: %s", err.Error())
			return
		}
		fsh.ServeHTTP(w, r)
	})
}

func proxyUpstream(w http.ResponseWriter, r *http.Request, file, upstream string) error {
	url, err := url.Parse(upstream)
	if err != nil {
		return err
	}

	r.Host = url.Host
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme

	httputil.NewSingleHostReverseProxy(url).ServeHTTP(w, r)
	return nil
}

func (s *server) static(prefix, root, upstream string) http.Handler {
	return http.StripPrefix(prefix, staticServer(root, upstream, s.keyDir))
}
