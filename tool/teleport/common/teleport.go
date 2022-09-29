/*
Copyright 2015-2021 Gravitational, Inc.

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

package common

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// Options combines init/start teleport options
type Options struct {
	// Args is a list of command-line args passed from main()
	Args []string
	// InitOnly when set to true, initializes config and aux
	// endpoints but does not start the process
	InitOnly bool
}

// Run inits/starts the process according to the provided options
func Run(options Options) (app *kingpin.Application, executedCommand string, conf *service.Config) {
	var err error

	// configure trace's errors to produce full stack traces
	isDebug, _ := strconv.ParseBool(os.Getenv(teleport.VerboseLogsEnvVar))
	if isDebug {
		trace.SetDebug(true)
	}
	// configure logger for a typical CLI scenario until configuration file is
	// parsed
	utils.InitLogger(utils.LoggingForDaemon, log.ErrorLevel)
	app = utils.InitCLIParser("teleport", "Teleport Access Plane. Learn more at https://goteleport.com")

	// define global flags:
	var (
		ccf config.CommandLineFlags
	)
	// XXIONG: we will hard-code to node only
	ccf.Roles = "node"

	// define commands:
	start := app.Command("start", "Starts the Teleport service.")
	ver := app.Command("version", "Print the version of your teleport binary.")
	exec := app.Command(teleport.ExecSubCommand, "Used internally by Teleport to re-exec itself to run a command.").Hidden()
	forward := app.Command(teleport.ForwardSubCommand, "Used internally by Teleport to re-exec itself to port forward.").Hidden()
	checkHomeDir := app.Command(teleport.CheckHomeDirSubCommand, "Used internally by Teleport to re-exec itself to check access to a directory.").Hidden()
	park := app.Command(teleport.ParkSubCommand, "Used internally by Teleport to re-exec itself to do nothing.").Hidden()
	app.HelpFlag.Short('h')

	// define start flags:
	start.Flag("debug", "Enable verbose logging to stderr").
		Short('d').
		BoolVar(&ccf.Debug)
	start.Flag("insecure-no-tls", "Disable TLS for the web socket").
		BoolVar(&ccf.DisableTLS)
	// start.Flag("roles",
	// 	fmt.Sprintf("Comma-separated list of roles to start with [%s]", strings.Join(defaults.StartRoles, ","))).
	// 	Short('r').
	// 	StringVar(&ccf.Roles)
	start.Flag("pid-file",
		"Full path to the PID file. By default no PID file will be created").StringVar(&ccf.PIDFile)
	start.Flag("advertise-ip",
		"IP to advertise to clients if running behind NAT").
		StringVar(&ccf.AdvertiseIP)
	start.Flag("listen-ip",
		fmt.Sprintf("IP address to bind to [%s]", defaults.BindIP)).
		Short('l').
		IPVar(&ccf.ListenIP)
	start.Flag("auth-server",
		fmt.Sprintf("Address of the auth server [%s]", defaults.AuthConnectAddr().Addr)).
		StringsVar(&ccf.AuthServerAddr)
	start.Flag("token",
		"Invitation token to register with an auth server [none]").
		StringVar(&ccf.AuthToken)
	start.Flag("ca-pin",
		"CA pin to validate the Auth Server (can be repeated for multiple pins)").
		StringsVar(&ccf.CAPins)
	start.Flag("nodename",
		"Name of this node, defaults to hostname").
		StringVar(&ccf.NodeName)
	start.Flag("config",
		fmt.Sprintf("Path to a configuration file [%v]", defaults.ConfigFilePath)).
		Short('c').ExistingFileVar(&ccf.ConfigFile)
	start.Flag("bootstrap",
		"Path to bootstrap file (ignored if already initialized)").ExistingFileVar(&ccf.BootstrapFile)
	start.Flag("config-string",
		"Base64 encoded configuration string").Hidden().Envar(defaults.ConfigEnvar).
		StringVar(&ccf.ConfigString)
	start.Flag("labels", "Comma-separated list of labels for this node, for example env=dev,app=web").StringVar(&ccf.Labels)
	start.Flag("diag-addr",
		"Start diagnostic prometheus and healthz endpoint.").StringVar(&ccf.DiagnosticAddr)
	start.Flag("permit-user-env",
		"Enables reading of ~/.tsh/environment when creating a session").BoolVar(&ccf.PermitUserEnvironment)
	start.Flag("insecure",
		"Insecure mode disables certificate validation").BoolVar(&ccf.InsecureMode)
	start.Flag("fips",
		"Start Teleport in FedRAMP/FIPS 140-2 mode.").
		Default("false").
		BoolVar(&ccf.FIPS)
	start.Flag("skip-version-check",
		"Skip version checking between server and client.").
		Default("false").
		BoolVar(&ccf.SkipVersionCheck)

	// define start's usage info (we use kingpin's "alias" field for this)
	start.Alias(usageNotes + usageExamples)

	// parse CLI commands+flags:
	utils.UpdateAppUsageTemplate(app, options.Args)
	command, err := app.Parse(options.Args)
	if err != nil {
		app.Usage(options.Args)
		utils.FatalError(err)
	}

	// Create default configuration.
	conf = service.MakeDefaultConfig()

	// If FIPS mode is specified update defaults to be FIPS appropriate and
	// cross-validate the current config.
	if ccf.FIPS {
		if ccf.InsecureMode {
			utils.FatalError(trace.BadParameter("--insecure not allowed in FIPS mode"))
		}
		service.ApplyFIPSDefaults(conf)
	}

	// execute the selected command unless we're running tests
	switch command {
	case start.FullCommand():
		// configuration merge: defaults -> file-based conf -> CLI conf
		if err = config.Configure(&ccf, conf); err != nil {
			utils.FatalError(err)
		}
		if !options.InitOnly {
			err = OnStart(conf)
		}
	case exec.FullCommand():
		srv.RunAndExit(teleport.ExecSubCommand)
	case forward.FullCommand():
		srv.RunAndExit(teleport.ForwardSubCommand)
	case checkHomeDir.FullCommand():
		srv.RunAndExit(teleport.CheckHomeDirSubCommand)
	case park.FullCommand():
		srv.RunAndExit(teleport.ParkSubCommand)
	case ver.FullCommand():
		utils.PrintVersion()
	}
	if err != nil {
		utils.FatalError(err)
	}
	return app, command, conf
}

// OnStart is the handler for "start" CLI command
func OnStart(config *service.Config) error {
	return service.Run(context.TODO(), *config, nil)
}
