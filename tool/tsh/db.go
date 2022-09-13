/*
Copyright 2020-2021 Gravitational, Inc.

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

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	dbprofile "github.com/gravitational/teleport/lib/client/db"
	"github.com/gravitational/teleport/lib/client/db/dbcmd"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	"github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/ghodss/yaml"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
)

// onListDatabases implements "tsh db ls" command.
func onListDatabases(cf *CLIConf) error {
	if cf.ListAll {
		return trace.Wrap(listDatabasesAllClusters(cf))
	}

	// Retrieve profile to be able to show which databases user is logged into.
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}

	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	var proxy *client.ProxyClient
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		proxy, err = tc.ConnectToProxy(cf.Context)
		return trace.Wrap(err)
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer proxy.Close()

	databases, err := proxy.FindDatabasesByFiltersForCluster(cf.Context, *tc.DefaultResourceFilter(), tc.SiteName)
	if err != nil {
		return trace.Wrap(err)
	}

	var roleSet services.RoleSet
	if isRoleSetRequiredForShowDatabases(cf) {
		roleSet, err = fetchRoleSetForCluster(cf.Context, profile, proxy, tc.SiteName)
		if err != nil {
			log.Debugf("Failed to fetch user roles: %v.", err)
		}
	}

	activeDatabases, err := profile.DatabasesForCluster(tc.SiteName)
	if err != nil {
		return trace.Wrap(err)
	}

	sort.Sort(types.Databases(databases))
	return trace.Wrap(showDatabases(cf.Stdout(), cf.SiteName, databases, activeDatabases, roleSet, cf.Format, cf.Verbose))
}

func isRoleSetRequiredForShowDatabases(cf *CLIConf) bool {
	return cf.Format == "" || teleport.Text == strings.ToLower(cf.Format)
}

func fetchRoleSetForCluster(ctx context.Context, profile *client.ProfileStatus, proxy *client.ProxyClient, clusterName string) (services.RoleSet, error) {
	cluster, err := proxy.ConnectToCluster(ctx, clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer cluster.Close()

	roleSet, err := services.FetchAllClusterRoles(ctx, cluster, profile.Roles, profile.Traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return roleSet, nil
}

type databaseListing struct {
	Proxy    string           `json:"proxy"`
	Cluster  string           `json:"cluster"`
	roleSet  services.RoleSet `json:"-"`
	Database types.Database   `json:"database"`
}

type databaseListings []databaseListing

func (l databaseListings) Len() int {
	return len(l)
}

func (l databaseListings) Less(i, j int) bool {
	if l[i].Proxy != l[j].Proxy {
		return l[i].Proxy < l[j].Proxy
	}
	if l[i].Cluster != l[j].Cluster {
		return l[i].Cluster < l[j].Cluster
	}
	return l[i].Database.GetName() < l[j].Database.GetName()
}

func (l databaseListings) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func listDatabasesAllClusters(cf *CLIConf) error {
	// Fetch database listings for profiles in parallel. Set an arbitrary limit
	// just in case.
	group, groupCtx := errgroup.WithContext(cf.Context)
	group.SetLimit(4)

	dbListingsResultChan := make(chan databaseListings)
	dbListingsCollectChan := make(chan databaseListings)
	go func() {
		var dbListings databaseListings
		for {
			select {
			case items := <-dbListingsCollectChan:
				dbListings = append(dbListings, items...)
			case <-groupCtx.Done():
				dbListingsResultChan <- dbListings
				return
			}
		}
	}()

	err := forEachProfile(cf, func(tc *client.TeleportClient, profile *client.ProfileStatus) error {
		group.Go(func() error {
			proxy, err := tc.ConnectToProxy(groupCtx)
			if err != nil {
				return trace.Wrap(err)
			}
			defer proxy.Close()

			sites, err := proxy.GetSites(groupCtx)
			if err != nil {
				return trace.Wrap(err)
			}

			var dbListings databaseListings
			for _, site := range sites {
				databases, err := proxy.FindDatabasesByFiltersForCluster(groupCtx, *tc.DefaultResourceFilter(), site.Name)
				if err != nil {
					return trace.Wrap(err)
				}

				var roleSet services.RoleSet
				if isRoleSetRequiredForShowDatabases(cf) {
					roleSet, err = fetchRoleSetForCluster(groupCtx, profile, proxy, site.Name)
					if err != nil {
						log.Debugf("Failed to fetch user roles: %v.", err)
					}
				}

				for _, database := range databases {
					dbListings = append(dbListings, databaseListing{
						Proxy:    profile.ProxyURL.Host,
						Cluster:  site.Name,
						roleSet:  roleSet,
						Database: database,
					})
				}
			}

			dbListingsCollectChan <- dbListings
			return nil
		})
		return nil
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if err := group.Wait(); err != nil {
		return trace.Wrap(err)
	}

	dbListings := <-dbListingsResultChan
	sort.Sort(dbListings)

	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}
	var active []tlsca.RouteToDatabase
	if profile != nil {
		active = profile.Databases
	}

	format := strings.ToLower(cf.Format)
	switch format {
	case teleport.Text, "":
		printDatabasesWithClusters(cf.SiteName, dbListings, active, cf.Verbose)
	case teleport.JSON, teleport.YAML:
		out, err := serializeDatabasesAllClusters(dbListings, format)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Println(out)
	default:
		return trace.BadParameter("unsupported format %q", format)
	}
	return nil
}

// onDatabaseLogin implements "tsh db login" command.
func onDatabaseLogin(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := getDatabase(cf, tc, cf.DatabaseService)
	if err != nil {
		return trace.Wrap(err)
	}
	routeToDatabase := tlsca.RouteToDatabase{
		ServiceName: cf.DatabaseService,
		Protocol:    database.GetProtocol(),
		Username:    cf.DatabaseUser,
		Database:    cf.DatabaseName,
	}

	if err := databaseLogin(cf, tc, routeToDatabase); err != nil {
		return trace.Wrap(err)
	}

	// Print after-login message.
	templateData := map[string]string{
		"name":           routeToDatabase.ServiceName,
		"connectCommand": utils.Color(utils.Yellow, formatDatabaseConnectCommand(cf.SiteName, routeToDatabase)),
	}

	if isLocalProxyRequiredForDatabase(tc, &routeToDatabase) {
		templateData["proxyCommand"] = utils.Color(utils.Yellow, formatDatabaseProxyCommand(cf.SiteName, routeToDatabase))
	} else {
		templateData["configCommand"] = utils.Color(utils.Yellow, formatDatabaseConfigCommand(cf.SiteName, routeToDatabase))
	}
	return trace.Wrap(dbConnectTemplate.Execute(cf.Stdout(), templateData))
}

func databaseLogin(cf *CLIConf, tc *client.TeleportClient, db tlsca.RouteToDatabase) error {
	log.Debugf("Fetching database access certificate for %s on cluster %v.", db, tc.SiteName)
	// When generating certificate for MongoDB access, database username must
	// be encoded into it. This is required to be able to tell which database
	// user to authenticate the connection as.
	if db.Protocol == defaults.ProtocolMongoDB && db.Username == "" {
		return trace.BadParameter("please provide the database user name using --db-user flag")
	}
	if db.Protocol == defaults.ProtocolRedis && db.Username == "" {
		// Default to "default" in the same way as Redis does. We need the username to check access on our side.
		// ref: https://redis.io/commands/auth
		db.Username = defaults.DefaultRedisUsername
	}

	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}

	// Identity files themselves act as the database credentials (if any), so
	// don't bother fetching new certs.
	if profile.IsVirtual {
		log.Info("Note: already logged in due to an identity file (`-i ...`); will only update database config files.")
	} else {
		var key *client.Key
		if err = client.RetryWithRelogin(cf.Context, tc, func() error {
			key, err = tc.IssueUserCertsWithMFA(cf.Context, client.ReissueParams{
				RouteToCluster: tc.SiteName,
				RouteToDatabase: proto.RouteToDatabase{
					ServiceName: db.ServiceName,
					Protocol:    db.Protocol,
					Username:    db.Username,
					Database:    db.Database,
				},
				AccessRequests: profile.ActiveRequests.AccessRequests,
			})
			return trace.Wrap(err)
		}); err != nil {
			return trace.Wrap(err)
		}
		if err = tc.LocalAgent().AddDatabaseKey(key); err != nil {
			return trace.Wrap(err)
		}
	}

	// Refresh the profile.
	profile, err = client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}
	// Update the database-specific connection profile file.
	err = dbprofile.Add(cf.Context, tc, db, *profile)
	return trace.Wrap(err)
}

// onDatabaseLogout implements "tsh db logout" command.
func onDatabaseLogout(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}
	activeDatabases, err := profile.DatabasesForCluster(tc.SiteName)
	if err != nil {
		return trace.Wrap(err)
	}

	if profile.IsVirtual {
		log.Info("Note: an identity file is in use (`-i ...`); will only update database config files.")
	}

	var logout []tlsca.RouteToDatabase
	// If database name wasn't given on the command line, log out of all.
	if cf.DatabaseService == "" {
		logout = activeDatabases
	} else {
		for _, db := range activeDatabases {
			if db.ServiceName == cf.DatabaseService {
				logout = append(logout, db)
			}
		}
		if len(logout) == 0 {
			return trace.BadParameter("Not logged into database %q",
				tc.DatabaseService)
		}
	}
	for _, db := range logout {
		if err := databaseLogout(tc, db, profile.IsVirtual); err != nil {
			return trace.Wrap(err)
		}
	}
	if len(logout) == 1 {
		fmt.Println("Logged out of database", logout[0].ServiceName)
	} else {
		fmt.Println("Logged out of all databases")
	}
	return nil
}

func databaseLogout(tc *client.TeleportClient, db tlsca.RouteToDatabase, virtual bool) error {
	// First remove respective connection profile.
	err := dbprofile.Delete(tc, db)
	if err != nil {
		return trace.Wrap(err)
	}

	// Then remove the certificate from the keystore, but only for real
	// profiles.
	if !virtual {
		err = tc.LogoutDatabase(db.ServiceName)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// onDatabaseEnv implements "tsh db env" command.
func onDatabaseEnv(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	if tc.TLSRoutingEnabled {
		return trace.BadParameter(dbCmdUnsupportedTLSRouting, cf.CommandWithBinary())
	}

	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	if !dbprofile.IsSupported(*database) {
		return trace.BadParameter(dbCmdUnsupportedDBProtocol,
			cf.CommandWithBinary(),
			defaults.ReadableDatabaseProtocol(database.Protocol),
		)
	}

	env, err := dbprofile.Env(tc, *database)
	if err != nil {
		return trace.Wrap(err)
	}

	format := strings.ToLower(cf.Format)
	switch format {
	case dbFormatText, "":
		for k, v := range env {
			fmt.Printf("export %v=%v\n", k, v)
		}
	case dbFormatJSON, dbFormatYAML:
		out, err := serializeDatabaseEnvironment(env, format)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Println(out)
	default:
		return trace.BadParameter("unsupported format %q", cf.Format)
	}

	return nil
}

func serializeDatabaseEnvironment(env map[string]string, format string) (string, error) {
	var out []byte
	var err error
	if format == dbFormatJSON {
		out, err = utils.FastMarshalIndent(env, "", "  ")
	} else {
		out, err = yaml.Marshal(env)
	}
	return string(out), trace.Wrap(err)
}

// onDatabaseConfig implements "tsh db config" command.
func onDatabaseConfig(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	if tc.TLSRoutingEnabled {
		return trace.BadParameter(dbCmdUnsupportedTLSRouting, cf.CommandWithBinary())
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	rootCluster, err := tc.RootClusterName(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}
	// Postgres proxy listens on web proxy port while MySQL proxy listens on
	// a separate port due to the specifics of the protocol.
	var host string
	var port int
	switch database.Protocol {
	case defaults.ProtocolPostgres, defaults.ProtocolCockroachDB:
		host, port = tc.PostgresProxyHostPort()
	case defaults.ProtocolMySQL:
		host, port = tc.MySQLProxyHostPort()
	case defaults.ProtocolMongoDB, defaults.ProtocolRedis, defaults.ProtocolSnowflake, defaults.ProtocolElasticsearch:
		host, port = tc.WebProxyHostPort()
	default:
		return trace.BadParameter(dbCmdUnsupportedDBProtocol,
			cf.CommandWithBinary(),
			defaults.ReadableDatabaseProtocol(database.Protocol),
		)
	}

	format := strings.ToLower(cf.Format)
	switch format {
	case dbFormatCommand:
		cmd, err := dbcmd.NewCmdBuilder(tc, profile, database, rootCluster,
			dbcmd.WithPrintFormat(),
			dbcmd.WithLogger(log),
		).GetConnectCommand()
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Println(strings.Join(cmd.Env, " "), cmd.Path, strings.Join(cmd.Args[1:], " "))
	case dbFormatJSON, dbFormatYAML:
		configInfo := &dbConfigInfo{
			database.ServiceName, host, port, database.Username,
			database.Database, profile.CACertPathForCluster(rootCluster),
			profile.DatabaseCertPathForCluster(tc.SiteName, database.ServiceName),
			profile.KeyPath(),
		}
		out, err := serializeDatabaseConfig(configInfo, format)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Println(out)
	default:
		fmt.Printf(`Name:      %v
Host:      %v
Port:      %v
User:      %v
Database:  %v
CA:        %v
Cert:      %v
Key:       %v
`,
			database.ServiceName, host, port, database.Username,
			database.Database, profile.CACertPathForCluster(rootCluster),
			profile.DatabaseCertPathForCluster(tc.SiteName, database.ServiceName), profile.KeyPath())
	}
	return nil
}

type dbConfigInfo struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user,omitempty"`
	Database string `json:"database,omitempty"`
	CA       string `json:"ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
}

func serializeDatabaseConfig(configInfo *dbConfigInfo, format string) (string, error) {
	var out []byte
	var err error
	if format == dbFormatJSON {
		out, err = utils.FastMarshalIndent(configInfo, "", "  ")
	} else {
		out, err = yaml.Marshal(configInfo)
	}
	return string(out), trace.Wrap(err)
}

// maybeStartLocalProxy starts local TLS ALPN proxy if needed depending on the
// connection scenario and returns a list of options to use in the connect
// command.
func maybeStartLocalProxy(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, db *tlsca.RouteToDatabase,
	database types.Database, rootClusterName string,
) ([]dbcmd.ConnectCommandFunc, error) {
	if !isLocalProxyRequiredForDatabase(tc, db) {
		return []dbcmd.ConnectCommandFunc{}, nil
	}

	// Some protocols (Snowflake, Elasticsearch) only works in the local tunnel mode.
	localProxyTunnel := cf.LocalProxyTunnel
	if db.Protocol == defaults.ProtocolSnowflake || db.Protocol == defaults.ProtocolElasticsearch {
		localProxyTunnel = true
	}

	log.Debugf("Starting local proxy")

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	opts, err := prepareLocalProxyOptions(&localProxyConfig{
		cliConf:          cf,
		teleportClient:   tc,
		profile:          profile,
		routeToDatabase:  db,
		database:         database,
		listener:         listener,
		localProxyTunnel: localProxyTunnel,
		rootClusterName:  rootClusterName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	lp, err := mkLocalProxy(cf.Context, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	go func() {
		defer listener.Close()
		if err := lp.Start(cf.Context); err != nil {
			log.WithError(err).Errorf("Failed to start local proxy")
		}
	}()

	addr, err := utils.ParseAddr(lp.GetAddr())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// When connecting over TLS, psql only validates hostname against presented
	// certificate's DNS names. As such, connecting to 127.0.0.1 will fail
	// validation, so connect to localhost.
	host := "localhost"
	return []dbcmd.ConnectCommandFunc{
		dbcmd.WithLocalProxy(host, addr.Port(0), profile.CACertPathForCluster(rootClusterName)),
	}, nil
}

// localProxyConfig is an argument pack used in prepareLocalProxyOptions().
type localProxyConfig struct {
	cliConf         *CLIConf
	teleportClient  *client.TeleportClient
	profile         *client.ProfileStatus
	routeToDatabase *tlsca.RouteToDatabase
	database        types.Database
	listener        net.Listener
	// localProxyTunnel keeps the same value as cliConf.LocalProxyTunnel, but
	// it's always true for Snowflake database. Value is copied here to not modify
	// cli arguments directly.
	localProxyTunnel bool
	rootClusterName  string
}

// prepareLocalProxyOptions created localProxyOpts needed to create local proxy from localProxyConfig.
func prepareLocalProxyOptions(arg *localProxyConfig) (localProxyOpts, error) {
	// If user requested no client auth, open an authenticated tunnel using
	// client cert/key of the database.
	certFile := arg.cliConf.LocalProxyCertFile
	keyFile := arg.cliConf.LocalProxyKeyFile
	if certFile == "" && arg.localProxyTunnel {
		certFile = arg.profile.DatabaseCertPathForCluster(arg.cliConf.SiteName, arg.routeToDatabase.ServiceName)
		keyFile = arg.profile.KeyPath()
	}

	opts := localProxyOpts{
		proxyAddr:               arg.teleportClient.WebProxyAddr,
		listener:                arg.listener,
		protocols:               []common.Protocol{common.Protocol(arg.routeToDatabase.Protocol)},
		insecure:                arg.cliConf.InsecureSkipVerify,
		certFile:                certFile,
		keyFile:                 keyFile,
		alpnConnUpgradeRequired: alpnproxy.IsALPNConnUpgradeRequired(arg.teleportClient.WebProxyAddr, arg.cliConf.InsecureSkipVerify),
	}

	// If ALPN connection upgrade is required, explicitly use the profile CAs
	// since the tunneled TLS routing connection serves the Host cert.
	if opts.alpnConnUpgradeRequired {
		profileCAs, err := utils.NewCertPoolFromPath(arg.profile.CACertPathForCluster(arg.rootClusterName))
		if err != nil {
			return localProxyOpts{}, trace.Wrap(err)
		}
		opts.rootCAs = profileCAs
	}

	// For SQL Server connections, local proxy must be configured with the
	// client certificate that will be used to route connections.
	if arg.routeToDatabase.Protocol == defaults.ProtocolSQLServer {
		opts.certFile = arg.profile.DatabaseCertPathForCluster("", arg.routeToDatabase.ServiceName)
		opts.keyFile = arg.profile.KeyPath()
	}

	// To set correct MySQL server version DB proxy needs additional protocol.
	if !arg.localProxyTunnel && arg.routeToDatabase.Protocol == defaults.ProtocolMySQL {
		if arg.database == nil {
			var err error
			arg.database, err = getDatabase(arg.cliConf, arg.teleportClient, arg.routeToDatabase.ServiceName)
			if err != nil {
				return localProxyOpts{}, trace.Wrap(err)
			}
		}

		mysqlServerVersionProto := mySQLVersionToProto(arg.database)
		if mysqlServerVersionProto != "" {
			opts.protocols = append(opts.protocols, common.Protocol(mysqlServerVersionProto))
		}
	}

	return opts, nil
}

// mySQLVersionToProto returns base64 encoded MySQL server version with MySQL protocol prefix.
// If version is not set in the past database an empty string is returned.
func mySQLVersionToProto(database types.Database) string {
	version := database.GetMySQLServerVersion()
	if version == "" {
		return ""
	}

	versionBase64 := base64.StdEncoding.EncodeToString([]byte(version))

	// Include MySQL server version
	return string(common.ProtocolMySQLWithVerPrefix) + versionBase64
}

// onDatabaseConnect implements "tsh db connect" command.
func onDatabaseConnect(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return trace.Wrap(err)
	}
	routeToDatabase, database, err := getDatabaseInfo(cf, tc, cf.DatabaseService)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := maybeDatabaseLogin(cf, tc, profile, routeToDatabase); err != nil {
		return trace.Wrap(err)
	}

	rootClusterName, err := tc.RootClusterName(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}

	opts, err := maybeStartLocalProxy(cf, tc, profile, routeToDatabase, database, rootClusterName)
	if err != nil {
		return trace.Wrap(err)
	}
	opts = append(opts, dbcmd.WithLogger(log))

	cmd, err := dbcmd.NewCmdBuilder(tc, profile, routeToDatabase, rootClusterName, opts...).GetConnectCommand()
	if err != nil {
		return trace.Wrap(err)
	}
	log.Debug(cmd.String())

	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	// Use io.MultiWriter to duplicate stderr to the capture writer. The
	// captured stderr can be used for diagnosing command failures. The capture
	// writer captures up to a fixed number to limit memory usage.
	peakStderr := utils.NewCaptureNBytesWriter(dbcmd.PeakStderrSize)
	cmd.Stderr = io.MultiWriter(os.Stderr, peakStderr)

	err = cmd.Run()
	if err != nil {
		return dbcmd.ConvertCommandError(cmd, err, string(peakStderr.Bytes()))
	}
	return nil
}

// getDatabaseInfo fetches information about the database from tsh profile is DB is active in profile. Otherwise,
// the ListDatabases endpoint is called.
func getDatabaseInfo(cf *CLIConf, tc *client.TeleportClient, dbName string) (*tlsca.RouteToDatabase, types.Database, error) {
	database, err := pickActiveDatabase(cf)
	if err == nil {
		return database, nil, nil
	}
	if !trace.IsNotFound(err) {
		return nil, nil, trace.Wrap(err)
	}
	db, err := getDatabase(cf, tc, dbName)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return &tlsca.RouteToDatabase{
		ServiceName: db.GetName(),
		Protocol:    db.GetProtocol(),
		Username:    cf.DatabaseUser,
		Database:    cf.DatabaseName,
	}, db, nil
}

func getDatabase(cf *CLIConf, tc *client.TeleportClient, dbName string) (types.Database, error) {
	var databases []types.Database
	err := client.RetryWithRelogin(cf.Context, tc, func() error {
		allDatabases, err := tc.ListDatabases(cf.Context, &proto.ListResourcesRequest{
			Namespace:           tc.Namespace,
			PredicateExpression: fmt.Sprintf(`name == "%s"`, dbName),
		})
		// Kept for fallback in case an older auth does not apply filters.
		// DELETE IN 11.0.0
		for _, database := range allDatabases {
			if database.GetName() == dbName {
				databases = append(databases, database)
			}
		}
		return trace.Wrap(err)
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(databases) == 0 {
		return nil, trace.NotFound(
			"database %q not found, use '%v' to see registered databases", dbName, formatDatabaseListCommand(cf.SiteName))
	}
	return databases[0], nil
}

func needDatabaseRelogin(cf *CLIConf, tc *client.TeleportClient, database *tlsca.RouteToDatabase, profile *client.ProfileStatus) (bool, error) {
	found := false
	activeDatabases, err := profile.DatabasesForCluster(tc.SiteName)
	if err != nil {
		return false, trace.Wrap(err)
	}

	for _, v := range activeDatabases {
		if v.ServiceName == database.ServiceName {
			found = true
		}
	}
	// database not found in active list of databases.
	if !found {
		return true, nil
	}

	// For database protocols where database username is encoded in client certificate like Mongo
	// check if the command line dbUser matches the encoded username in database certificate.
	userChanged, err := dbInfoHasChanged(cf, profile.DatabaseCertPathForCluster(tc.SiteName, database.ServiceName))
	if err != nil {
		return false, trace.Wrap(err)
	}
	if userChanged {
		return true, nil
	}

	// Call API and check is a user needs to use MFA to connect to the database.
	mfaRequired, err := isMFADatabaseAccessRequired(cf, tc, database)
	if err != nil {
		return false, trace.Wrap(err)
	}
	return mfaRequired, nil
}

// maybeDatabaseLogin checks if cert is still valid or DB connection requires
// MFA. If yes trigger db login logic.
func maybeDatabaseLogin(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, db *tlsca.RouteToDatabase) error {
	reloginNeeded, err := needDatabaseRelogin(cf, tc, db, profile)
	if err != nil {
		return trace.Wrap(err)
	}

	if reloginNeeded {
		return trace.Wrap(databaseLogin(cf, tc, *db))
	}
	return nil
}

// dbInfoHasChanged checks if cliConf.DatabaseUser or cliConf.DatabaseName info has changed in the user database certificate.
func dbInfoHasChanged(cf *CLIConf, certPath string) (bool, error) {
	if cf.DatabaseUser == "" && cf.DatabaseName == "" {
		return false, nil
	}

	buff, err := os.ReadFile(certPath)
	if err != nil {
		return false, trace.Wrap(err)
	}
	cert, err := tlsca.ParseCertificatePEM(buff)
	if err != nil {
		return false, trace.Wrap(err)
	}
	identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	if err != nil {
		return false, trace.Wrap(err)
	}

	if cf.DatabaseUser != "" && cf.DatabaseUser != identity.RouteToDatabase.Username {
		log.Debugf("Will reissue database certificate for user %s (was %s)", cf.DatabaseUser, identity.RouteToDatabase.Username)
		return true, nil
	}
	if cf.DatabaseName != "" && cf.DatabaseName != identity.RouteToDatabase.Database {
		log.Debugf("Will reissue database certificate for database name %s (was %s)", cf.DatabaseName, identity.RouteToDatabase.Database)
		return true, nil
	}
	return false, nil
}

// isMFADatabaseAccessRequired calls the IsMFARequired endpoint in order to get from user roles if access to the database
// requires MFA.
func isMFADatabaseAccessRequired(cf *CLIConf, tc *client.TeleportClient, database *tlsca.RouteToDatabase) (bool, error) {
	proxy, err := tc.ConnectToProxy(cf.Context)
	if err != nil {
		return false, trace.Wrap(err)
	}
	cluster, err := proxy.ConnectToCluster(cf.Context, tc.SiteName)
	if err != nil {
		return false, trace.Wrap(err)
	}
	defer cluster.Close()

	dbParam := proto.RouteToDatabase{
		ServiceName: database.ServiceName,
		Protocol:    database.Protocol,
		Username:    database.Username,
		Database:    database.Database,
	}
	mfaResp, err := cluster.IsMFARequired(cf.Context, &proto.IsMFARequiredRequest{
		Target: &proto.IsMFARequiredRequest_Database{
			Database: &dbParam,
		},
	})
	if err != nil {
		return false, trace.Wrap(err)
	}
	return mfaResp.GetRequired(), nil
}

// pickActiveDatabase returns the database the current profile is logged into.
//
// If logged into multiple databases, returns an error unless one specified
// explicitly via --db flag.
func pickActiveDatabase(cf *CLIConf) (*tlsca.RouteToDatabase, error) {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy, cf.IdentityFileIn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	activeDatabases, err := profile.DatabasesForCluster(cf.SiteName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(activeDatabases) == 0 {
		return nil, trace.NotFound("Please login using 'tsh db login' first")
	}

	name := cf.DatabaseService
	if name == "" {
		if len(activeDatabases) > 1 {
			var services []string
			for _, database := range activeDatabases {
				services = append(services, database.ServiceName)
			}
			return nil, trace.BadParameter("Multiple databases are available (%v), please specify one using CLI argument",
				strings.Join(services, ", "))
		}
		name = activeDatabases[0].ServiceName
	}
	for _, db := range activeDatabases {
		if db.ServiceName == name {
			// If database user or name were provided on the CLI,
			// override the default ones.
			if cf.DatabaseUser != "" {
				db.Username = cf.DatabaseUser
			}
			if cf.DatabaseName != "" {
				db.Database = cf.DatabaseName
			}
			return &db, nil
		}
	}
	return nil, trace.NotFound("Not logged into database %q", name)
}

func formatDatabaseListCommand(clusterFlag string) string {
	if clusterFlag == "" {
		return "tsh db ls"
	}
	return fmt.Sprintf("tsh db ls --cluster=%v", clusterFlag)
}

// formatDatabaseConnectCommand formats an appropriate database connection
// command for a user based on the provided database parameters.
func formatDatabaseConnectCommand(clusterFlag string, active tlsca.RouteToDatabase) string {
	cmdTokens := append(
		[]string{"tsh", "db", "connect"},
		formatDatabaseConnectArgs(clusterFlag, active)...,
	)
	return strings.Join(cmdTokens, " ")
}

// formatDatabaseConnectArgs generates the arguments for "tsh db connect" command.
func formatDatabaseConnectArgs(clusterFlag string, active tlsca.RouteToDatabase) (flags []string) {
	if clusterFlag != "" {
		flags = append(flags, fmt.Sprintf("--cluster=%s", clusterFlag))
	}
	if active.Username == "" {
		flags = append(flags, "--db-user=<user>")
	}
	if active.Database == "" {
		flags = append(flags, "--db-name=<name>")
	}
	flags = append(flags, active.ServiceName)
	return
}

// formatDatabaseProxyCommand formats the "tsh proxy db" command.
func formatDatabaseProxyCommand(clusterFlag string, active tlsca.RouteToDatabase) string {
	cmdTokens := append(
		// "--tunnel" mode is more user friendly and supports all DB protocols.
		[]string{"tsh", "proxy", "db", "--tunnel"},
		// Rest of the args are the same as "tsh db connect".
		formatDatabaseConnectArgs(clusterFlag, active)...,
	)
	return strings.Join(cmdTokens, " ")
}

// formatDatabaseConfigCommand formats the "tsh db config" command.
func formatDatabaseConfigCommand(clusterFlag string, db tlsca.RouteToDatabase) string {
	if clusterFlag == "" {
		return fmt.Sprintf("tsh db config --format=cmd %v", db.ServiceName)
	}
	return fmt.Sprintf("tsh db config --cluster=%v --format=cmd %v", clusterFlag, db.ServiceName)
}

// isLocalProxyRequiredForDatabase returns true if local proxy has to be used
// for connecting to the provided database. Currently return true if:
//   - TLS routing is enabled.
//   - A SQL Server connection always requires a local proxy.
func isLocalProxyRequiredForDatabase(tc *client.TeleportClient, db *tlsca.RouteToDatabase) bool {
	return tc.TLSRoutingEnabled || db.Protocol == defaults.ProtocolSQLServer
}

const (
	// dbFormatText prints database configuration in text format.
	dbFormatText = "text"
	// dbFormatCommand prints database connection command.
	dbFormatCommand = "cmd"
	// dbFormatJSON prints database info as JSON.
	dbFormatJSON = "json"
	// dbFormatYAML prints database info as YAML.
	dbFormatYAML = "yaml"
)

const (
	// dbCmdUnsupportedTLSRouting is the error message printed when some
	// database subcommands are not supported because TLS routing is enabled.
	dbCmdUnsupportedTLSRouting = `"%v" is not supported when TLS routing is enabled on the Teleport Proxy Service.

Please use "tsh db connect" or "tsh proxy db" to connect to the database.`

	// dbCmdUnsupportedDBProtocol is the error message printed when some
	// database subcommands are run against unsupported database protocols.
	dbCmdUnsupportedDBProtocol = `"%v" is not supported for %v databases.

Please use "tsh db connect" or "tsh proxy db" to connect to the database.`
)

var (
	// dbConnectTemplate is the message printed after a successful "tsh db login" on how to connect.
	dbConnectTemplate = template.Must(template.New("").Parse(`Connection information for database "{{ .name }}" has been saved.

You can now connect to it using the following command:

  {{.connectCommand}}

{{if .configCommand -}}
Or view the connect command for the native database CLI client:

  {{ .configCommand }}

{{end -}}
{{if .proxyCommand -}}
Or start a local proxy for database GUI clients:

  {{ .proxyCommand }}

{{end -}}
`))
)
