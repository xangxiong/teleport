/*
Copyright 2017-2021 Gravitational, Inc.

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

// package modules allows external packages override certain behavioral
// aspects of teleport
package modules

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"runtime"
	"sync"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"

	"github.com/gravitational/trace"
)

// Features provides supported and unsupported features
type Features struct {
	// AccessControls enables FIPS access controls
	AccessControls bool
	// AdvancedAccessWorkflows enables advanced access workflows
	AdvancedAccessWorkflows bool
	// HSM enables PKCS#11 HSM support
	HSM bool
	// ModeratedSessions turns on moderated sessions
	ModeratedSessions bool
	// MachineID turns on MachineID
	MachineID bool
	// ResourceAccessRequests turns on resource access requests
	ResourceAccessRequests bool
}

// ToProto converts Features into proto.Features
func (f Features) ToProto() *proto.Features {
	return &proto.Features{
		AccessControls:          f.AccessControls,
		AdvancedAccessWorkflows: f.AdvancedAccessWorkflows,
		HSM:                     f.HSM,
		ModeratedSessions:       f.ModeratedSessions,
		MachineID:               f.MachineID,
		ResourceAccessRequests:  f.ResourceAccessRequests,
	}
}

// Modules defines interface that external libraries can implement customizing
// default teleport behavior
type Modules interface {
	// PrintVersion prints teleport version
	PrintVersion()
	// IsBoringBinary checks if the binary was compiled with BoringCrypto.
	IsBoringBinary() bool
	// Features returns supported features
	Features() Features
	// BuildType returns build type (OSS or Enterprise)
	BuildType() string
}

const (
	// BuildOSS specifies open source build type
	BuildOSS = "oss"
	// BuildEnterprise specifies enterprise build type
	BuildEnterprise = "ent"
)

// SetModules sets the modules interface
func SetModules(m Modules) {
	mutex.Lock()
	defer mutex.Unlock()
	modules = m
}

// GetModules returns the modules interface
func GetModules() Modules {
	mutex.Lock()
	defer mutex.Unlock()
	return modules
}

// ValidateResource performs additional resource checks.
func ValidateResource(res types.Resource) error {
	switch r := res.(type) {
	case types.AuthPreference:
		switch r.GetSecondFactor() {
		case constants.SecondFactorOff, constants.SecondFactorOptional:
			return trace.BadParameter("cannot disable two-factor authentication on Cloud")
		}
	case types.SessionRecordingConfig:
		switch r.GetMode() {
		case types.RecordAtProxy, types.RecordAtProxySync:
			return trace.BadParameter("cannot set proxy recording mode on Cloud")
		}
		if !r.GetProxyChecksHostKeys() {
			return trace.BadParameter("cannot disable strict host key checking on Cloud")
		}
	}
	return nil
}

type defaultModules struct{}

// BuildType returns build type (OSS or Enterprise)
func (p *defaultModules) BuildType() string {
	return BuildOSS
}

// PrintVersion prints the Teleport version.
func (p *defaultModules) PrintVersion() {
	fmt.Printf("Teleport v%s git:%s %s\n", teleport.Version, teleport.Gitref, runtime.Version())
}

// Features returns supported features
func (p *defaultModules) Features() Features {
	return Features{
		MachineID:         true,
		ModeratedSessions: false, // moderated sessions is supported in enterprise only
	}
}

func (p *defaultModules) IsBoringBinary() bool {
	// Check the package name for one of the boring primitives, if the package
	// path is from BoringCrypto, we know this binary was compiled against the
	// dev.boringcrypto branch of Go.
	hash := sha256.New()
	return reflect.TypeOf(hash).Elem().PkgPath() == "crypto/internal/boring"
}

var (
	mutex   sync.Mutex
	modules Modules = &defaultModules{}
)
