//go:build webassets_embed
// +build webassets_embed

/*
Copyright 2021 Gravitational, Inc.

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

package web

// import (
// 	"embed"
// 	"io/fs"
// 	"net/http"

// 	"github.com/gravitational/trace"
// )

// //go:embed build/webassets
// var webassetFS embed.FS

// // NewStaticFileSystem returns the initialized implementation of http.FileSystem
// // interface which can be used to serve Teleport Proxy Web UI
// func NewStaticFileSystem() (http.FileSystem, error) {
// 	wfs, err := fs.Sub(webassetFS, "build/webassets")
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	return http.FS(wfs), nil
// }
