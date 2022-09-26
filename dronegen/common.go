// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// import (
// 	"bytes"
// 	"fmt"
// 	"log"
// 	"os/exec"
// 	"path"
// 	"strings"
// )

// const (
// 	// StagingRegistry is the staging registry images are pushed to before being promoted to the production registry.
// 	StagingRegistry = "146628656107.dkr.ecr.us-west-2.amazonaws.com"

// 	// ProductionRegistry is the production image registry that hosts are customer facing container images.
// 	ProductionRegistry = "public.ecr.aws"

// 	// ProductionRegistryQuay is the production image registry that hosts images on quay.io. Will be deprecated in the future.
// 	// See RFD 73 - https://github.com/gravitational/teleport/blob/c18c09f5d562dd46a509154eab4295ad39decc3c/rfd/0073-public-image-registry.md
// 	ProductionRegistryQuay = "quay.io"
// )

// var (
// 	triggerPush = trigger{
// 		Event:  triggerRef{Include: []string{"push"}, Exclude: []string{"pull_request"}},
// 		Branch: triggerRef{Include: []string{"master", "branch/*"}},
// 		Repo:   triggerRef{Include: []string{"gravitational/*"}},
// 	}
// 	triggerTag = trigger{
// 		Event: triggerRef{Include: []string{"tag"}},
// 		Ref:   triggerRef{Include: []string{"refs/tags/v*"}},
// 		Repo:  triggerRef{Include: []string{"gravitational/*"}},
// 	}
// 	triggerPromote = trigger{
// 		Event:  triggerRef{Include: []string{"promote"}},
// 		Target: triggerRef{Include: []string{"production"}},
// 		Repo:   triggerRef{Include: []string{"gravitational/*"}},
// 	}

// 	volumeDocker = volume{
// 		Name: "dockersock",
// 		Temp: &volumeTemp{},
// 	}
// 	volumeTmpfs = volume{
// 		Name: "tmpfs",
// 		Temp: &volumeTemp{Medium: "memory"},
// 	}
// 	volumeRefTmpfs = volumeRef{
// 		Name: "tmpfs",
// 		Path: "/tmpfs",
// 	}
// 	volumeRefDocker = volumeRef{
// 		Name: "dockersock",
// 		Path: "/var/run",
// 	}
// )

// var buildboxVersion value

// var goRuntime value

// func init() {
// 	v, err := exec.Command("make", "-s", "-C", "build.assets", "print-go-version").Output()
// 	if err != nil {
// 		log.Fatalf("could not get Go version: %v", err)
// 	}
// 	goRuntime = value{raw: string(bytes.TrimSpace(v))}

// 	v, err = exec.Command("make", "-s", "-C", "build.assets", "print-buildbox-version").Output()
// 	if err != nil {
// 		log.Fatalf("could not get buildbox version: %v", err)
// 	}
// 	buildboxVersion = value{raw: string(bytes.TrimSpace(v))}
// }

// func pushTriggerForBranch(branches ...string) trigger {
// 	t := trigger{
// 		Event: triggerRef{Include: []string{"push"}},
// 		Repo:  triggerRef{Include: []string{"gravitational/teleport"}},
// 	}
// 	t.Branch.Include = append(t.Branch.Include, branches...)
// 	return t
// }

// func cloneRepoCommands(cloneDirectory, commit string) []string {
// 	return []string{
// 		fmt.Sprintf("mkdir -pv %q", cloneDirectory),
// 		fmt.Sprintf("cd %q", cloneDirectory),
// 		`git init && git remote add origin ${DRONE_REMOTE_URL}`,
// 		`git fetch origin`,
// 		fmt.Sprintf("git checkout -qf %q", commit),
// 	}
// }

// type buildType struct {
// 	os              string
// 	arch            string
// 	fips            bool
// 	centos7         bool
// 	windowsUnsigned bool
// }

// // Description provides a human-facing description of the artifact, e.g.:
// //
// //	Windows 64-bit (tsh client only)
// //	Linux ARMv7 (32-bit)
// //	MacOS Intel .pkg installer
// func (b *buildType) Description(packageType string, extraQualifications ...string) string {
// 	var result string

// 	var os string
// 	var arch string
// 	var darwinArch string
// 	var bitness int
// 	var qualifications []string

// 	switch b.os {
// 	case "linux":
// 		os = "Linux"
// 	case "darwin":
// 		os = "MacOS"
// 	case "windows":
// 		os = "Windows"
// 	default:
// 		panic(fmt.Sprintf("unhandled OS: %s", b.os))
// 	}

// 	switch b.arch {
// 	case "arm64":
// 		arch = "ARM64/ARMv8"
// 		darwinArch = "Apple Silicon"
// 		bitness = 64
// 	case "amd64":
// 		darwinArch = "Intel"
// 		bitness = 64

// 	case "arm":
// 		arch = "ARMv7"
// 		fallthrough
// 	case "386":
// 		bitness = 32

// 	default:
// 		panic(fmt.Sprintf("unhandled arch: %s", b.arch))
// 	}

// 	if b.centos7 {
// 		qualifications = append(qualifications, "RHEL/CentOS 7.x compatible")
// 	}
// 	if b.fips {
// 		qualifications = append(qualifications, "FedRAMP/FIPS")
// 	}

// 	qualifications = append(qualifications, extraQualifications...)

// 	result = os

// 	if b.os == "darwin" {
// 		result += fmt.Sprintf(" %s", darwinArch)
// 	} else {
// 		// arch is implicit for Windows/Linux i386/amd64
// 		if arch == "" {
// 			result += fmt.Sprintf(" %d-bit", bitness)
// 		} else {
// 			result += fmt.Sprintf(" %s (%d-bit)", arch, bitness)
// 		}
// 	}

// 	if packageType != "" {
// 		result += fmt.Sprintf(" %s", packageType)
// 	}

// 	if len(qualifications) > 0 {
// 		result += fmt.Sprintf(" (%s)", strings.Join(qualifications, ", "))
// 	}
// 	return result
// }

// func (b *buildType) hasTeleportConnect() bool {
// 	return (b.os == "darwin" && b.arch == "amd64") ||
// 		(b.os == "linux" && b.arch == "amd64" && !b.centos7 && !b.fips)
// }

// // dockerService generates a docker:dind service
// // It includes the Docker socket volume by default, plus any extra volumes passed in
// func dockerService(v ...volumeRef) service {
// 	return service{
// 		Name:       "Start Docker",
// 		Image:      "docker:dind",
// 		Privileged: true,
// 		Volumes:    append(v, volumeRefDocker),
// 	}
// }

// // dockerVolumes returns a slice of volumes
// // It includes the Docker socket volume by default, plus any extra volumes passed in
// func dockerVolumes(v ...volume) []volume {
// 	return append(v, volumeDocker)
// }

// // dockerVolumeRefs returns a slice of volumeRefs
// // It includes the Docker socket volumeRef as a default, plus any extra volumeRefs passed in
// func dockerVolumeRefs(v ...volumeRef) []volumeRef {
// 	return append(v, volumeRefDocker)
// }

// // releaseMakefileTarget gets the correct Makefile target for a given arch/fips/centos combo
// func releaseMakefileTarget(b buildType) string {
// 	makefileTarget := fmt.Sprintf("release-%s", b.arch)
// 	// All x86_64 binaries are built on CentOS 7 now for better glibc compatibility.
// 	if b.centos7 || b.arch == "amd64" {
// 		makefileTarget += "-centos7"
// 	}
// 	if b.fips {
// 		makefileTarget += "-fips"
// 	}

// 	// Override Windows targets.
// 	if b.os == "windows" {
// 		if b.windowsUnsigned {
// 			makefileTarget = "release-windows-unsigned"
// 		} else {
// 			makefileTarget = "release-windows"
// 		}
// 	}

// 	return makefileTarget
// }

// // waitForDockerStep returns a step which checks that the Docker socket is active before trying
// // to run container operations
// func waitForDockerStep() step {
// 	return step{
// 		Name:  "Wait for docker",
// 		Image: "docker",
// 		Commands: []string{
// 			`timeout 30s /bin/sh -c 'while [ ! -S /var/run/docker.sock ]; do sleep 1; done'`,
// 		},
// 		Volumes: dockerVolumeRefs(),
// 	}
// }

// func verifyValidPromoteRunSteps(checkoutPath, commit string, isParallelismEnabled bool) []step {
// 	tagStep := verifyTaggedStep()
// 	cloneStep := cloneRepoStep(checkoutPath, commit)
// 	verifyStep := verifyNotPrereleaseStep(checkoutPath)

// 	if isParallelismEnabled {
// 		cloneStep.DependsOn = []string{tagStep.Name}
// 		verifyStep.DependsOn = []string{cloneStep.Name}
// 	}

// 	return []step{tagStep, cloneStep, verifyStep}
// }

// func verifyTaggedStep() step {
// 	return step{
// 		Name:  "Verify build is tagged",
// 		Image: "alpine:latest",
// 		Commands: []string{
// 			"[ -n ${DRONE_TAG} ] || (echo 'DRONE_TAG is not set. Is the commit tagged?' && exit 1)",
// 		},
// 	}
// }

// // Note that tags are also valid here as a tag refers to a specific commit
// func cloneRepoStep(clonePath, commit string) step {
// 	return step{
// 		Name:     "Check out code",
// 		Image:    "alpine/git:latest",
// 		Commands: cloneRepoCommands(clonePath, commit),
// 	}
// }

// func verifyNotPrereleaseStep(checkoutPath string) step {
// 	return step{
// 		Name:  "Check if tag is prerelease",
// 		Image: "golang:1.18-alpine",
// 		Commands: []string{
// 			fmt.Sprintf("cd %q", path.Join(checkoutPath, "build.assets", "tooling")),
// 			"go run ./cmd/check -tag ${DRONE_TAG} -check prerelease || (echo '---> This is a prerelease, not continuing promotion for ${DRONE_TAG}' && exit 78)",
// 		},
// 	}
// }
