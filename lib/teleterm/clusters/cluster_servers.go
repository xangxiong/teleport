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

package clusters

import (
	"context"
	"github.com/gravitational/teleport/lib/sshutils/scp"
	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"io"
	"os"
	"time"

	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"

	"github.com/gravitational/trace"
)

// Database describes database
type Server struct {
	// URI is the database URI
	URI uri.ResourceURI

	types.Server
}

// GetServers returns cluster servers
func (c *Cluster) GetServers(ctx context.Context) ([]Server, error) {
	proxyClient, err := c.clusterClient.ConnectToProxy(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer proxyClient.Close()

	clusterServers, err := proxyClient.FindServersByLabels(ctx, defaults.Namespace, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	results := []Server{}
	for _, server := range clusterServers {
		results = append(results, Server{
			URI:    c.URI.AppendServer(server.GetName()),
			Server: server,
		})
	}

	return results, nil
}

func (c *Cluster) DownloadSCP(request *api.DownloadRequest, server api.TerminalService_DownloadServer) error {
	flags := scp.Flags{
		Target: []string{request.GetFilename()},
	}

	cfg := scp.Config{
		Flags: flags,
		User:  c.GetLoggedInUser().Name,
		//ProgressWriter: req.Progress,
		RemoteLocation: request.GetLocation(),
		FileSystem: &grpcFileSystem{
			writer: &grpcWriter{DownloadServer: server},
		},
	}
	cmd, err := scp.CreateDownloadCommand(cfg)

	if err != nil {
		return trace.Wrap(err)
	}

	c.clusterClient.Config.Host = "my_root" // TODO remove hardcoded value
	c.clusterClient.Config.HostPort = 3022  // TODO remove hardcoded value

	err = c.clusterClient.ExecuteSCP(server.Context(), cmd)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

type grpcWriter struct {
	DownloadServer api.TerminalService_DownloadServer
}

func (writer *grpcWriter) Write(p []byte) (n int, err error) {
	println("GRPC Write")
	err = writer.DownloadServer.Send(&api.DataChunk{Data: p})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (writer *grpcWriter) Close() error {
	println("GRPC close")
	return nil
}

// httpFileSystem simulates file system calls while using HTTP response/request streams.
type grpcFileSystem struct {
	writer   io.WriteCloser
	reader   io.ReadCloser
	fileName string
	fileSize int64
}

// Chmod sets file permissions. It does nothing as there are no permissions
// while processing HTTP downloads
func (l *grpcFileSystem) Chmod(path string, mode int) error {
	return nil
}

// Chtimes sets file access and modification time.
// It is a no-op for the HTTP file system implementation
func (l *grpcFileSystem) Chtimes(path string, atime, mtime time.Time) error {
	return nil
}

// MkDir creates a directory. This method is not implemented as creating directories
// is not supported during HTTP downloads.
func (l *grpcFileSystem) MkDir(path string, mode int) error {
	return trace.BadParameter("directories are not supported in http file transfer")
}

// IsDir tells if this file is a directory. It always returns false as
// directories are not supported in HTTP file transfer
func (l *grpcFileSystem) IsDir(path string) bool {
	return false
}

// OpenFile returns file reader
func (l *grpcFileSystem) OpenFile(filePath string) (io.ReadCloser, error) {
	if l.reader == nil {
		return nil, trace.BadParameter("missing reader")
	}

	return l.reader, nil
}

// CreateFile sets proper HTTP headers and returns HTTP writer to stream incoming
// file content
func (l *grpcFileSystem) CreateFile(filePath string, length uint64) (io.WriteCloser, error) {
	//_, filename := filepath.Split(filePath)
	//contentLength := strconv.FormatUint(length, 10)
	//header := l.writer.Header()
	//
	//httplib.SetNoCacheHeaders(header)
	//httplib.SetNoSniff(header)
	//header.Set("Content-Length", contentLength)
	//header.Set("Content-Type", "application/octet-stream")
	//filename = url.QueryEscape(filename)
	//header.Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%v"`, filename))

	return &grpcWriter{}, nil // in http version we use here nopWriteCloser, but it doesn't seem to make a difference
}

// GetFileInfo returns file information
func (l *grpcFileSystem) GetFileInfo(filePath string) (scp.FileInfo, error) {
	return &scpFileInfo{
		name: l.fileName,
		path: l.fileName,
		size: l.fileSize,
	}, nil
}

// httpFileInfo is implementation of FileInfo interface used during HTTP
// file transfer
type scpFileInfo struct {
	path string
	name string
	size int64
}

// IsDir tells if this file in a directory
func (l *scpFileInfo) IsDir() bool {
	return false
}

// GetName returns file name
func (l *scpFileInfo) GetName() string {
	return l.name
}

// GetPath returns file path
func (l *scpFileInfo) GetPath() string {
	return l.path
}

// GetSize returns file size
func (l *scpFileInfo) GetSize() int64 {
	return l.size
}

// ReadDir returns an slice of files in the directory.
// This method is not supported in HTTP file transfer
func (l *scpFileInfo) ReadDir() ([]scp.FileInfo, error) {
	return nil, trace.BadParameter("directories are not supported in http file transfer")
}

// GetModePerm returns file permissions that will be set on the
// file created on the remote host during HTTP upload.
func (l *scpFileInfo) GetModePerm() os.FileMode {
	return 0644
}

// GetModTime returns file modification time.
// It is a no-op for HTTP file information
func (l *scpFileInfo) GetModTime() time.Time {
	return time.Time{}
}

// GetAccessTime returns file last access time.
// It is a no-op for HTTP file information
func (l *scpFileInfo) GetAccessTime() time.Time {
	return time.Time{}
}

type nopWriteCloser struct {
}

func (wr *nopWriteCloser) Close() error {
	println("NOP close")
	return nil
}

func (wr *nopWriteCloser) Write([]byte) (int, error) {
	println("NOP Write")
	return 0, nil
}
