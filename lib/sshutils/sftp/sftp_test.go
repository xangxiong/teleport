/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sftp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
)

const (
	fileMaxSize = 1000
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

func TestUpload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		srcPaths    []string
		dstPath     string
		opts        Options
		files       []string
		expectedErr string
	}{
		{
			name: "one file",
			srcPaths: []string{
				"file",
			},
			dstPath: "copied-file",
			opts: Options{
				PreserveAttrs: true,
			},
			files: []string{
				"file",
			},
		},
		{
			name: "one dir",
			srcPaths: []string{
				"src/",
			},
			dstPath: "dir/",
			opts: Options{
				PreserveAttrs: true,
				Recursive:     true,
			},
			files: []string{
				"src/",
			},
		},
		{
			name: "two files dst doesn't exist",
			srcPaths: []string{
				"src/file1",
				"src/file2",
			},
			dstPath: "dst/",
			opts: Options{
				PreserveAttrs: true,
			},
			files: []string{
				"src/file1",
				"src/file2",
			},
		},
		{
			name: "two files dst does exist",
			srcPaths: []string{
				"src/file1",
				"src/file2",
			},
			dstPath: "dst/",
			opts: Options{
				PreserveAttrs: true,
			},
			files: []string{
				"src/file1",
				"src/file2",
				"dst/",
			},
		},
		{
			name: "nested dirs",
			srcPaths: []string{
				"s",
			},
			dstPath: "dst/",
			opts: Options{
				PreserveAttrs: true,
				Recursive:     true,
			},
			files: []string{
				"s/",
				"s/file",
				"s/r/",
				"s/r/file",
				"s/r/c/",
				"s/r/c/file",
				"dst/",
			},
		},
		{
			name: "multiple src dst not dir",
			srcPaths: []string{
				"uno",
				"dos",
				"tres",
			},
			dstPath: "dst_file",
			files: []string{
				"uno",
				"dos",
				"tres",
				"dst_file",
			},
			expectedErr: `local file "%s/dst_file" is not a directory, but multiple source files were specified`,
		},
		{
			name: "src dir with recursive not passed",
			srcPaths: []string{
				"src/",
			},
			dstPath: "dst/",
			files: []string{
				"src/",
			},
			expectedErr: `"%s/src" is a directory, but the recursive option was not passed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create necessary files
			tempDir := t.TempDir()
			for _, file := range tt.files {
				// if path ends in slash, create dir
				if strings.HasSuffix(file, string(filepath.Separator)) {
					createDir(t, tempDir, file)
				} else {
					createFile(t, tempDir, file)
				}
			}
			for i := range tt.srcPaths {
				tt.srcPaths[i] = filepath.Join(tempDir, tt.srcPaths[i])
			}
			tt.dstPath = filepath.Join(tempDir, tt.dstPath)

			ctx := context.Background()
			cfg := CreateUploadConfig(tt.srcPaths, tt.dstPath, tt.opts)
			// use all local filesystems to avoid SSH overhead
			cfg.dstFS = &localFS{}
			cfg.initFS(ctx, nil)

			err := cfg.transfer(ctx)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				checkTransfer(t, tt.opts.PreserveAttrs, tt.dstPath, tt.srcPaths...)
			} else {
				require.EqualError(t, err, fmt.Sprintf(tt.expectedErr, tempDir))
			}
		})
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		srcPath     string
		dstPath     string
		opts        Options
		files       []string
		expectedErr string
	}{
		{
			name:    "one file",
			srcPath: "file",
			dstPath: "copied-file",
			opts: Options{
				PreserveAttrs: true,
			},
			files: []string{
				"file",
			},
		},
		{
			name:    "one dir",
			srcPath: "src/",
			dstPath: "dst/",
			opts: Options{
				PreserveAttrs: true,
				Recursive:     true,
			},
			files: []string{
				"src/",
				"s/file",
				"s/r/",
				"s/r/file",
				"s/r/c/",
				"s/r/c/file",
				"dst/",
			},
		},
		{
			name:    "src dir with recursive not passed",
			srcPath: "src/",
			dstPath: "dst/",
			files: []string{
				"src/",
			},
			expectedErr: `"%s/src" is a directory, but the recursive option was not passed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create necessary files
			tempDir := t.TempDir()
			for _, file := range tt.files {
				// if path ends in slash, create dir
				if strings.HasSuffix(file, string(filepath.Separator)) {
					createDir(t, tempDir, file)
				} else {
					createFile(t, tempDir, file)
				}
			}
			tt.srcPath = filepath.Join(tempDir, tt.srcPath)
			tt.dstPath = filepath.Join(tempDir, tt.dstPath)

			ctx := context.Background()
			cfg := CreateDownloadConfig(tt.srcPath, tt.dstPath, tt.opts)
			// use all local filesystems to avoid SSH overhead
			cfg.srcFS = &localFS{}
			cfg.initFS(ctx, nil)

			err := cfg.transfer(ctx)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				checkTransfer(t, tt.opts.PreserveAttrs, tt.dstPath, tt.srcPath)
			} else {
				require.EqualError(t, err, fmt.Sprintf(tt.expectedErr, tempDir))
			}
		})
	}
}

func createFile(t *testing.T, rootDir, path string) {
	dir := filepath.Dir(path)
	if dir != path {
		createDir(t, rootDir, dir)
	}

	f, err := os.Create(filepath.Join(rootDir, path))
	if err != nil {
		t.Fatalf("error creating file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("error closing file: %v", err)
		}
	}()

	// populate file with random amount of random contents
	r := rand.New(rand.NewSource(time.Now().Unix()))
	lr := io.LimitReader(r, r.Int63n(fileMaxSize)+1)
	_, err = io.Copy(f, lr)
	if err != nil {
		t.Fatalf("error writing to file: %v", err)
	}
}

func createDir(t *testing.T, rootDir, path string) {
	err := os.MkdirAll(filepath.Join(rootDir, path), 0777)
	if err != nil {
		t.Fatalf("error creating directory: %v", err)
	}
}

func checkTransfer(t *testing.T, preserveAttrs bool, dst string, srcs ...string) {
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("error getting dst file info: %v", err)
	}
	if !dstInfo.IsDir() && len(srcs) > 1 {
		t.Fatalf("multiple src files specified, but dst is not a directory")
	}
	if !dstInfo.IsDir() {
		compareFiles(t, preserveAttrs, dstInfo, nil, dst, srcs[0])
		return
	}

	for _, src := range srcs {
		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatalf("error getting src file info: %v", err)
		}

		// src is file, compare files
		if !srcInfo.IsDir() {
			dstSubPath := filepath.Join(dst, filepath.Base(src))
			dstSubInfo, err := os.Stat(dstSubPath)
			if err != nil {
				t.Fatalf("error getting dst file info: %v", err)
			}
			if dstSubInfo.IsDir() {
				t.Fatalf("dst file is directory: %q", dstSubPath)
			}
			compareFiles(t, preserveAttrs, dstSubInfo, srcInfo, dstSubPath, src)
			continue
		}

		// src is dir, compare dir trees
		err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// skip comparing the root src dir
			if path == src {
				return nil
			}

			relPath := strings.TrimPrefix(path, src)
			dstPath := filepath.Join(dst, relPath)
			dstInfo, err := os.Stat(dstPath)
			if err != nil {
				return fmt.Errorf("error getting dst file info: %v", err)
			}
			if info.IsDir() != dstInfo.IsDir() {
				t.Fatalf("expected %q IsDir=%t, got %t", dstPath, info.IsDir(), dstInfo.IsDir())
			}

			if dstInfo.IsDir() {
				compareFileInfos(t, preserveAttrs, dstInfo, info, dstPath, path)
			} else {
				compareFiles(t, preserveAttrs, dstInfo, info, dstPath, path)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("error walking src dir: %v", err)
		}
	}
}

func compareFiles(t *testing.T, preserveAttrs bool, dstInfo, srcInfo os.FileInfo, dst, src string) {
	var err error
	if srcInfo == nil {
		srcInfo, err = os.Stat(src)
		if err != nil {
			t.Fatalf("error getting dst file info: %v", err)
		}
	}

	compareFileInfos(t, preserveAttrs, dstInfo, srcInfo, dst, src)

	dstBytes, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("error reading dst file: %v", err)
	}
	srcBytes, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("error reading src file: %v", err)
	}
	if !bytes.Equal(dstBytes, srcBytes) {
		t.Errorf("%q and %q contents not equal", dst, src[0])
	}
}

func compareFileInfos(t *testing.T, preserveAttrs bool, dstInfo, srcInfo os.FileInfo, dst, src string) {
	if dstInfo.Size() != srcInfo.Size() {
		t.Fatalf("%q and %q sizes not equal", dst, src)
	}
	if dstInfo.Mode() != srcInfo.Mode() {
		t.Errorf("%q and %q perms not equal", dst, src)
	}

	if preserveAttrs {
		if !dstInfo.ModTime().Equal(srcInfo.ModTime()) {
			t.Errorf("%q and %q mod times not equal", dst, src)
		}
		if !getAtime(dstInfo).Equal(getAtime(srcInfo)) {
			t.Errorf("%q and %q access times not equal", dst, src)
		}
	}
}
