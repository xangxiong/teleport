/*
Copyright 2015-2020 Gravitational, Inc.

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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/modules"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
)

// ThisFunction returns calling function name
func ThisFunction() string {
	var pc [32]uintptr
	runtime.Callers(2, pc[:])
	return runtime.FuncForPC(pc[0]).Name()
}

// ClickableURL fixes address in url to make sure
// it's clickable, e.g. it replaces "undefined" address like
// 0.0.0.0 used in network listeners format with loopback 127.0.0.1
func ClickableURL(in string) string {
	out, err := url.Parse(in)
	if err != nil {
		return in
	}
	host, port, err := net.SplitHostPort(out.Host)
	if err != nil {
		return in
	}
	ip := net.ParseIP(host)
	// if address is not an IP, unspecified, e.g. all interfaces 0.0.0.0 or multicast,
	// replace with localhost that is clickable
	if len(ip) == 0 || ip.IsUnspecified() || ip.IsMulticast() {
		out.Host = fmt.Sprintf("127.0.0.1:%v", port)
		return out.String()
	}
	return out.String()
}

// AsBool converts string to bool, in case of the value is empty
// or unknown, defaults to false
func AsBool(v string) bool {
	if v == "" {
		return false
	}
	out, _ := apiutils.ParseBool(v)
	return out
}

// ParseAdvertiseAddr validates advertise address,
// makes sure it's not an unreachable or multicast address
// returns address split into host and port, port could be empty
// if not specified
func ParseAdvertiseAddr(advertiseIP string) (string, string, error) {
	advertiseIP = strings.TrimSpace(advertiseIP)
	host := advertiseIP
	port := ""
	if len(net.ParseIP(host)) == 0 && strings.Contains(advertiseIP, ":") {
		var err error
		host, port, err = net.SplitHostPort(advertiseIP)
		if err != nil {
			return "", "", trace.BadParameter("failed to parse address %q", advertiseIP)
		}
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", trace.BadParameter("bad port %q, expected integer", port)
		}
		if host == "" {
			return "", "", trace.BadParameter("missing host parameter")
		}
	}
	ip := net.ParseIP(host)
	if len(ip) != 0 {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", "", trace.BadParameter("unreachable advertise IP: %v", advertiseIP)
		}
	}
	return host, port, nil
}

// StringsSliceFromSet returns a sorted strings slice from set
func StringsSliceFromSet(in map[string]struct{}) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// StringsSet creates set of string (map[string]struct{})
// from a list of strings
func StringsSet(in []string) map[string]struct{} {
	if in == nil {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{})
	for _, v := range in {
		out[v] = struct{}{}
	}
	return out
}

// SplitHostPort splits host and port and checks that host is not empty
func SplitHostPort(hostname string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return "", "", trace.Wrap(err)
	}
	if host == "" {
		return "", "", trace.BadParameter("empty hostname")
	}
	return host, port, nil
}

// ReadPath reads file contents
func ReadPath(path string) ([]byte, error) {
	if path == "" {
		return nil, trace.NotFound("empty path")
	}
	s, err := filepath.Abs(path)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	abs, err := filepath.EvalSymlinks(s)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			//do not convert to system error as this loses the ability to compare that it is a permission error
			return nil, err
		}
		return nil, trace.ConvertSystemError(err)
	}
	bytes, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			//do not convert to system error as this loses the ability to compare that it is a permission error
			return nil, err
		}
		return nil, trace.ConvertSystemError(err)
	}
	return bytes, nil
}

// IsHandshakeFailedError specifies whether this error indicates
// failed handshake
func IsHandshakeFailedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(trace.Unwrap(err).Error(), "ssh: handshake failed")
}

// IsCertExpiredError specifies whether this error indicates
// expired SSH certificate
func IsCertExpiredError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(trace.Unwrap(err).Error(), "ssh: cert has expired")
}

// OpaqueAccessDenied returns a generic NotFound instead of AccessDenied
// so as to avoid leaking the existence of secret resources.
func OpaqueAccessDenied(err error) error {
	if trace.IsAccessDenied(err) {
		return trace.NotFound("not found")
	}
	return trace.Wrap(err)
}

// ReadHostUUID reads host UUID from the file in the data dir
func ReadHostUUID(dataDir string) (string, error) {
	out, err := ReadPath(filepath.Join(dataDir, HostUUIDFile))
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			//do not convert to system error as this loses the ability to compare that it is a permission error
			return "", err
		}
		return "", trace.ConvertSystemError(err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		return "", trace.NotFound("host uuid is empty")
	}
	return id, nil
}

// WriteHostUUID writes host UUID into a file
func WriteHostUUID(dataDir string, id string) error {
	err := os.WriteFile(filepath.Join(dataDir, HostUUIDFile), []byte(id), os.ModeExclusive|0400)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			//do not convert to system error as this loses the ability to compare that it is a permission error
			return err
		}
		return trace.ConvertSystemError(err)
	}
	return nil
}

// ReadOrMakeHostUUID looks for a hostid file in the data dir. If present,
// returns the UUID from it, otherwise generates one
func ReadOrMakeHostUUID(dataDir string) (string, error) {
	id, err := ReadHostUUID(dataDir)
	if err == nil {
		return id, nil
	}
	if !trace.IsNotFound(err) {
		return "", trace.Wrap(err)
	}
	// Checking error instead of the usual uuid.New() in case uuid generation
	// fails due to not enough randomness. It's been known to happen happen when
	// Teleport starts very early in the node initialization cycle and /dev/urandom
	// isn't ready yet.
	rawID, err := uuid.NewRandom()
	if err != nil {
		return "", trace.BadParameter("" +
			"Teleport failed to generate host UUID. " +
			"This may happen if randomness source is not fully initialized when the node is starting up. " +
			"Please try restarting Teleport again.")
	}
	id = rawID.String()
	if err = WriteHostUUID(dataDir, id); err != nil {
		return "", trace.Wrap(err)
	}
	return id, nil
}

// PrintVersion prints human readable version
func PrintVersion() {
	modules.GetModules().PrintVersion()
}

// StringSliceSubset returns true if b is a subset of a.
func StringSliceSubset(a []string, b []string) error {
	aset := make(map[string]bool)
	for _, v := range a {
		aset[v] = true
	}

	for _, v := range b {
		_, ok := aset[v]
		if !ok {
			return trace.BadParameter("%v not in set", v)
		}

	}
	return nil
}

// UintSliceSubset returns true if b is a subset of a.
func UintSliceSubset(a []uint16, b []uint16) error {
	aset := make(map[uint16]bool)
	for _, v := range a {
		aset[v] = true
	}

	for _, v := range b {
		_, ok := aset[v]
		if !ok {
			return trace.BadParameter("%v not in set", v)
		}

	}
	return nil
}

// RemoveFromSlice makes a copy of the slice and removes the passed in values from the copy.
func RemoveFromSlice(slice []string, values ...string) []string {
	output := make([]string, 0, len(slice))

	remove := make(map[string]bool)
	for _, value := range values {
		remove[value] = true
	}

	for _, s := range slice {
		_, ok := remove[s]
		if ok {
			continue
		}
		output = append(output, s)
	}

	return output
}

// ChooseRandomString returns a random string from the given slice.
func ChooseRandomString(slice []string) string {
	switch len(slice) {
	case 0:
		return ""
	case 1:
		return slice[0]
	default:
		return slice[rand.Intn(len(slice))]
	}
}

// ReadAtMost reads up to limit bytes from r, and reports an error
// when limit bytes are read.
func ReadAtMost(r io.Reader, limit int64) ([]byte, error) {
	limitedReader := &io.LimitedReader{R: r, N: limit}
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return data, err
	}
	if limitedReader.N <= 0 {
		return data, ErrLimitReached
	}
	return data, nil
}

// ErrLimitReached means that the read limit is reached.
var ErrLimitReached = &trace.LimitExceededError{Message: "the read limit is reached"}

const (
	// CertTeleportUser specifies teleport user
	CertTeleportUser = "x-teleport-user"
	// CertExtensionRole specifies teleport role
	CertExtensionRole = "x-teleport-role"
	// CertExtensionAuthority specifies teleport authority's name
	// that signed this domain
	CertExtensionAuthority = "x-teleport-authority"
	// HostUUIDFile is the file name where the host UUID file is stored
	HostUUIDFile = "host_uuid"
	// CertTeleportClusterName is a name of the teleport cluster
	CertTeleportClusterName = "x-teleport-cluster-name"
	// CertTeleportUserCertificate is the certificate of the authenticated in user.
	CertTeleportUserCertificate = "x-teleport-certificate"
	// ExtIntCertType is an internal extension used to propagate cert type.
	ExtIntCertType = "certtype@teleport"
	// ExtIntCertTypeHost indicates a host-type certificate.
	ExtIntCertTypeHost = "host"
	// ExtIntCertTypeUser indicates a user-type certificate.
	ExtIntCertTypeUser = "user"
)
