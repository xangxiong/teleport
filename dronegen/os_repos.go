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

import (
	"fmt"
	"path"
	"strings"
)

func promoteBuildOsRepoPipelines() []pipeline {
	aptPipeline := promoteAptPipeline()
	yumPipeline := promoteYumPipeline()
	return []pipeline{
		aptPipeline,
		yumPipeline,
	}
}

// Used for one-off migrations of older versions.
// Use cases include:
//   - We want to support another OS while providing backwards compatibility
//   - We want to support another OS version while providing backwards compatibility
//   - A customer wants to be able to install an older version via APT/YUM even if we
//     no longer support it
//   - RPM migrations after new YUM pipeline is done
func artifactMigrationPipeline() []pipeline {
	migrationVersions := []string{
		// These versions were migrated as a part of the new `promoteAptPipeline`
		// "v6.2.31",
		// "v7.3.17",
		// "v7.3.18",
		// "v7.3.19",
		// "v7.3.20",
		// "v7.3.21",
		// "v7.3.23",
		// "v8.3.3",
		// "v8.3.4",
		// "v8.3.5",
		// "v8.3.6",
		// "v8.3.7",
		// "v8.3.8",
		// "v8.3.9",
		// "v8.3.10",
		// "v8.3.11",
		// "v8.3.12",
		// "v8.3.14",
		// "v8.3.15",
		// "v8.3.16",
		// "v9.0.0",
		// "v9.0.1",
		// "v9.0.2",
		// "v9.0.3",
		// "v9.0.4",
		// "v9.1.0",
		// "v9.1.1",
		// "v9.1.2",
		// "v9.1.3",
		// "v9.2.0",
		// "v9.2.1",
		// "v9.2.2",
		// "v9.2.3",
		// "v9.2.4",
		// "v9.3.0",
		// "v9.3.2",
		// "v9.3.4",
		// "v9.3.5",
		// "v9.3.6",
		// "v9.3.7",
		// "v9.3.9",
		// "v9.3.10",
		// "v9.3.12",
		// "v9.3.13",
		// "v10.0.0",
		// "v10.0.1",
		// "v10.0.2",
	}
	// Pushing to this branch will trigger the listed versions to be migrated. Typically this should be
	// the branch that these changes are being committed to.
	migrationBranch := "" // "rfd/0058-package-distribution"

	aptPipeline := migrateAptPipeline(migrationBranch, migrationVersions)
	yumPipeline := migrateYumPipeline(migrationBranch, migrationVersions)
	return []pipeline{
		aptPipeline,
		yumPipeline,
	}
}

type RepoBucketSecretNames struct {
	bucketName      string
	accessKeyID     string
	secretAccessKey string
}

func NewRepoBucketSecretNames(bucketName, accessKeyID, secretAccessKey string) *RepoBucketSecretNames {
	return &RepoBucketSecretNames{
		bucketName:      bucketName,
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
	}
}

type OsPackageToolPipelineBuilder struct {
	clameName          string
	packageType        string
	packageManagerName string
	volumeName         string
	pipelineNameSuffix string
	artifactPath       string
	pvcMountPoint      string
	bucketSecrets      *RepoBucketSecretNames
	extraArgs          []string
	requiredPackages   []string
	setupCommands      []string
	environmentVars    map[string]value
}

// This function configures the build tool with it's requirements and sensible defaults.
// If additional configuration required then the returned struct should be modified prior
// to calling "build" functions on it.
func NewOsPackageToolPipelineBuilder(claimName, packageType, packageManagerName string, bucketSecrets *RepoBucketSecretNames) *OsPackageToolPipelineBuilder {
	optpb := &OsPackageToolPipelineBuilder{
		clameName:          claimName,
		packageType:        packageType,
		packageManagerName: packageManagerName,
		bucketSecrets:      bucketSecrets,
		extraArgs:          []string{},
		setupCommands:      []string{},
		requiredPackages:   []string{},
		volumeName:         fmt.Sprintf("%s-persistence", packageManagerName),
		pipelineNameSuffix: fmt.Sprintf("%s-new-repos", packageManagerName),
		artifactPath:       "/go/artifacts",
		pvcMountPoint:      "/mnt",
	}

	optpb.environmentVars = map[string]value{
		"REPO_S3_BUCKET": {
			fromSecret: optpb.bucketSecrets.bucketName,
		},
		"AWS_ACCESS_KEY_ID": {
			fromSecret: optpb.bucketSecrets.accessKeyID,
		},
		"AWS_SECRET_ACCESS_KEY": {
			fromSecret: optpb.bucketSecrets.secretAccessKey,
		},
		"AWS_REGION": {
			raw: "us-west-2",
		},
		"BUCKET_CACHE_PATH": {
			// If we need to cache the bucket on the PVC for some reason in the future
			// uncomment this line
			// raw: path.Join(pvcMountPoint, "bucket-cache"),
			raw: "/tmp/bucket",
		},
		"ARTIFACT_PATH": {
			raw: optpb.artifactPath,
		},
		"GNUPGHOME": {
			raw: "/tmpfs/gnupg",
		},
		"GPG_RPM_SIGNING_ARCHIVE": {
			fromSecret: "GPG_RPM_SIGNING_ARCHIVE",
		},
		"DEBIAN_FRONTEND": {
			raw: "noninteractive",
		},
	}

	return optpb
}

func (optpb *OsPackageToolPipelineBuilder) buildPromoteOsPackagePipeline() pipeline {
	pipelineName := fmt.Sprintf("publish-%s", optpb.pipelineNameSuffix)
	checkoutPath := "/go/src/github.com/gravitational/teleport"
	commitName := "${DRONE_TAG}"
	checkoutStepName := "Check out code"

	p := optpb.buildBaseOsPackagePipeline(pipelineName, checkoutStepName, checkoutPath, commitName)
	p.Trigger = triggerPromote
	p.Trigger.Repo.Include = []string{"gravitational/teleport"}

	setupSteps := []step{
		{
			Name:  "Verify build is tagged",
			Image: "alpine:latest",
			Commands: []string{
				"[ -n ${DRONE_TAG} ] || (echo 'DRONE_TAG is not set. Is the commit tagged?' && exit 1)",
			},
		},
	}
	setupSteps = append(setupSteps, p.Steps...)
	setupSteps = append(setupSteps,
		step{
			Name:  "Check if tag is prerelease",
			Image: "golang:1.17-alpine",
			Commands: []string{
				fmt.Sprintf("cd %q", path.Join(checkoutPath, "build.assets", "tooling")),
				"go run ./cmd/check -tag ${DRONE_TAG} -check prerelease || (echo '---> This is a prerelease, not publishing ${DRONE_TAG} packages to APT repos' && exit 78)",
			},
		},
	)

	setupStepNames := make([]string, 0, len(setupSteps))
	for _, setupStep := range setupSteps {
		setupStepNames = append(setupStepNames, setupStep.Name)
	}

	versionSteps := optpb.getDroneTagVersionSteps(checkoutPath)
	for i := range versionSteps {
		versionStep := &versionSteps[i]
		if versionStep.DependsOn == nil {
			versionStep.DependsOn = setupStepNames
			continue
		}

		versionStep.DependsOn = append(versionStep.DependsOn, setupStepNames...)
	}

	p.Steps = append(setupSteps, versionSteps...)

	return p
}

func (optpb *OsPackageToolPipelineBuilder) buildMigrateOsPackagePipeline(triggerBranch string, migrationVersions []string) pipeline {
	pipelineName := fmt.Sprintf("migrate-%s", optpb.pipelineNameSuffix)
	checkoutPath := "/go/src/github.com/gravitational/teleport"
	// DRONE_TAG is not available outside of promotion pipelines and will cause drone to fail with a
	// "migrate-apt-new-repos: bad substitution" error if used here
	commitName := "${DRONE_COMMIT}"
	checkoutStepName := "Check out code"

	// If migrations are not configured then don't run
	if triggerBranch == "" || len(migrationVersions) == 0 {
		return buildNeverTriggerPipeline(pipelineName)
	}

	p := optpb.buildBaseOsPackagePipeline(pipelineName, checkoutStepName, checkoutPath, commitName)
	p.Trigger = trigger{
		Repo:   triggerRef{Include: []string{"gravitational/teleport"}},
		Event:  triggerRef{Include: []string{"push"}},
		Branch: triggerRef{Include: []string{triggerBranch}},
	}

	for _, migrationVersion := range migrationVersions {
		// Not enabling parallelism here so that multiple migrations don't run at once
		p.Steps = append(p.Steps, optpb.getVersionSteps(checkoutPath, migrationVersion, false)...)
	}

	setStepResourceLimits(p.Steps)

	return p
}

// Builds a pipeline that is syntactically correct but should never trigger to create
// a placeholder pipeline
func buildNeverTriggerPipeline(pipelineName string) pipeline {
	p := newKubePipeline(pipelineName)
	p.Trigger = trigger{
		Event:  triggerRef{Include: []string{"custom"}},
		Repo:   triggerRef{Include: []string{"non-existent-repository"}},
		Branch: triggerRef{Include: []string{"non-existent-branch"}},
	}

	p.Steps = []step{
		{
			Name:  "Placeholder",
			Image: "alpine:latest",
			Commands: []string{
				"echo \"This command, step, and pipeline never runs\"",
			},
		},
	}

	return p
}

// Functions that use this method should add at least:
// * a Trigger
// * Steps for checkout
func (optpb *OsPackageToolPipelineBuilder) buildBaseOsPackagePipeline(pipelineName, checkoutStepName, checkoutPath, commit string) pipeline {
	p := newKubePipeline(pipelineName)
	p.Workspace = workspace{Path: "/go"}
	p.Volumes = []volume{
		{
			Name: optpb.volumeName,
			Claim: &volumeClaim{
				Name: optpb.clameName,
			},
		},
		volumeTmpfs,
	}
	p.Steps = []step{
		{
			Name:     checkoutStepName,
			Image:    "alpine/git:latest",
			Commands: toolCheckoutCommands(checkoutPath, commit),
		},
	}
	setStepResourceLimits(p.Steps)

	return p
}

func setStepResourceLimits(steps []step) {
	// Not currently supported
	// for i := range steps {
	// 	step := &steps[i]
	// 	if step.Resources == nil {
	// 		step.Resources = &containerResources{}
	// 	}

	// 	if step.Resources.Requests == nil {
	// 		step.Resources.Requests = &resourceSet{}
	// 	}

	// 	step.Resources.Requests.Cpu = 100
	// 	step.Resources.Requests.Memory = (*resourceQuantity)(resource.NewQuantity(100*1024*1024, resource.BinarySI))
	// }
}

// Note that tags are also valid here as a tag refers to a specific commit
func toolCheckoutCommands(checkoutPath, commit string) []string {
	commands := []string{
		fmt.Sprintf("mkdir -p %q", checkoutPath),
		fmt.Sprintf("cd %q", checkoutPath),
		`git clone https://github.com/gravitational/${DRONE_REPO_NAME}.git .`,
		fmt.Sprintf("git checkout %q", commit),
	}
	return commands
}

func (optpb *OsPackageToolPipelineBuilder) getDroneTagVersionSteps(codePath string) []step {
	return optpb.getVersionSteps(codePath, "${DRONE_TAG}", true)
}

// Version should start with a 'v', i.e. v1.2.3 or v9.0.1, or should be an environment var
// i.e. ${DRONE_TAG}
func (optpb *OsPackageToolPipelineBuilder) getVersionSteps(codePath, version string, enableParallelism bool) []step {
	var bucketFolder string
	switch version[0:1] {
	// If environment var
	case "$":
		// Remove the 'v' at runtime as the value isn't known at compile time
		// This will change "${SOME_VAR}" to "${SOME_VAR##v}". `version` isn't actually
		// an environment variable - it's a Drone substitution variable. See
		// https://docs.drone.io/pipeline/environment/substitution/ for details.
		bucketFolder = fmt.Sprintf("%s##v}", version[:len(version)-1])
	// If static string
	case "v":
		// Remove the 'v' at compile time as the value is known then
		bucketFolder = version[1:]
	}

	toolSetupCommands := []string{}
	if len(optpb.requiredPackages) > 0 {
		toolSetupCommands = []string{
			"apt update",
			fmt.Sprintf("apt install -y %s", strings.Join(optpb.requiredPackages, " ")),
		}
	}
	toolSetupCommands = append(toolSetupCommands, optpb.setupCommands...)

	downloadStepName := fmt.Sprintf("Download artifacts for %q", version)
	buildStepDependencies := []string{}
	if enableParallelism {
		buildStepDependencies = append(buildStepDependencies, downloadStepName)
	}

	return []step{
		{
			Name:  downloadStepName,
			Image: "amazon/aws-cli",
			Environment: map[string]value{
				"AWS_S3_BUCKET": {
					fromSecret: "AWS_S3_BUCKET",
				},
				"AWS_ACCESS_KEY_ID": {
					fromSecret: "AWS_ACCESS_KEY_ID",
				},
				"AWS_SECRET_ACCESS_KEY": {
					fromSecret: "AWS_SECRET_ACCESS_KEY",
				},
				"ARTIFACT_PATH": {
					raw: optpb.artifactPath,
				},
			},
			Commands: []string{
				"mkdir -pv \"$ARTIFACT_PATH\"",
				// Clear out old versions from previous steps
				"rm -rf \"${ARTIFACT_PATH}/*\"",
				strings.Join(
					[]string{
						"aws s3 sync",
						"--no-progress",
						"--delete",
						"--exclude \"*\"",
						fmt.Sprintf("--include \"*.%s*\"", optpb.packageType),
						fmt.Sprintf("s3://$AWS_S3_BUCKET/teleport/tag/%s/", bucketFolder),
						"\"$ARTIFACT_PATH\"",
					},
					" ",
				),
			},
		},
		{
			Name:        fmt.Sprintf("Publish %ss to %s repos for %q", optpb.packageType, strings.ToUpper(optpb.packageManagerName), version),
			Image:       "golang:1.18.4-bullseye",
			Environment: optpb.environmentVars,
			Commands: append(
				toolSetupCommands,
				[]string{
					"mkdir -pv -m0700 \"$GNUPGHOME\"",
					"echo \"$GPG_RPM_SIGNING_ARCHIVE\" | base64 -d | tar -xzf - -C $GNUPGHOME",
					"chown -R root:root \"$GNUPGHOME\"",
					fmt.Sprintf("cd %q", path.Join(codePath, "build.assets", "tooling")),
					fmt.Sprintf("export VERSION=%q", version),
					"export RELEASE_CHANNEL=\"stable\"", // The tool supports several release channels but I'm not sure where this should be configured
					strings.Join(
						append(
							[]string{
								// This just makes the (long) command a little more readable
								"go run ./cmd/build-os-package-repos",
								optpb.packageManagerName,
								"-bucket \"$REPO_S3_BUCKET\"",
								"-local-bucket-path \"$BUCKET_CACHE_PATH\"",
								"-artifact-version \"$VERSION\"",
								"-release-channel \"$RELEASE_CHANNEL\"",
								"-artifact-path \"$ARTIFACT_PATH\"",
								"-log-level 4", // Set this to 5 for debug logging
							},
							optpb.extraArgs...,
						),
						" ",
					),
				}...,
			),
			Volumes: []volumeRef{
				{
					Name: optpb.volumeName,
					Path: optpb.pvcMountPoint,
				},
				volumeRefTmpfs,
			},
			DependsOn: buildStepDependencies,
		},
	}
}
