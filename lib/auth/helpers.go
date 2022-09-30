/*
Copyright 2017-2019 Gravitational, Inc.

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

package auth

import (
	"os"
	"path/filepath"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/tlsca"
)

// CreateUploaderDir creates directory for file uploader service
func CreateUploaderDir(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, teleport.LogsDir, teleport.ComponentUpload,
		events.StreamingLogsDir, apidefaults.Namespace), teleport.SharedDirMode); err != nil {
		return trace.ConvertSystemError(err)
	}

	return nil
}

// PrivateKeyToPublicKeyTLS gets the TLS public key from a raw private key.
func PrivateKeyToPublicKeyTLS(privateKey []byte) (tlsPublicKey []byte, err error) {
	sshPrivate, err := ssh.ParseRawPrivateKey(privateKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsPublicKey, err = tlsca.MarshalPublicKeyFromPrivateKeyPEM(sshPrivate)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return tlsPublicKey, nil
}
