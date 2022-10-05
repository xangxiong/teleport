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

package utils

import (
	"context"

	"github.com/gravitational/trace/trail"

	"google.golang.org/grpc"
)

// grpcClientStreamWrapper wraps around the embedded grpc.ClientStream
// and intercepts the RecvMsg and SendMsg method calls converting errors to the
// appropriate grpc status error.
type grpcClientStreamWrapper struct {
	grpc.ClientStream
}

// SendMsg wraps around ClientStream.SendMsg
func (s *grpcClientStreamWrapper) SendMsg(m interface{}) error {
	return trail.FromGRPC(s.ClientStream.SendMsg(m))
}

// RecvMsg wraps around ClientStream.RecvMsg
func (s *grpcClientStreamWrapper) RecvMsg(m interface{}) error {
	return trail.FromGRPC(s.ClientStream.RecvMsg(m))
}

// GRPCClientStreamErrorInterceptor is GPRC client stream interceptor that
// handles converting errors to the appropriate grpc status error.
func GRPCClientStreamErrorInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	s, err := streamer(ctx, desc, cc, method, opts...)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}
	return &grpcClientStreamWrapper{s}, nil
}
