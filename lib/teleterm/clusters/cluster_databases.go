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

// import (
// 	"context"

// 	"github.com/gravitational/teleport/api/client/proto"
// 	"github.com/gravitational/teleport/api/defaults"
// 	"github.com/gravitational/teleport/api/types"
// 	"github.com/gravitational/teleport/lib/auth"
// 	"github.com/gravitational/teleport/lib/client"
// 	dbprofile "github.com/gravitational/teleport/lib/client/db"
// 	libdefaults "github.com/gravitational/teleport/lib/defaults"
// 	"github.com/gravitational/teleport/lib/services"
// 	"github.com/gravitational/teleport/lib/teleterm/api/uri"
// 	"github.com/gravitational/teleport/lib/tlsca"

// 	"github.com/gravitational/trace"
// )

// // Database describes database
// type Database struct {
// 	// URI is the database URI
// 	URI uri.ResourceURI
// 	types.Database
// }

// // GetDatabase returns a database
// func (c *Cluster) GetDatabase(ctx context.Context, dbURI string) (*Database, error) {
// 	// TODO(ravicious): Fetch a single db instead of filtering the response from GetDatabases.
// 	// https://github.com/gravitational/teleport/pull/14690#discussion_r927720600
// 	dbs, err := c.GetDatabases(ctx)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	for _, db := range dbs {
// 		if db.URI.String() == dbURI {
// 			return &db, nil
// 		}
// 	}

// 	return nil, trace.NotFound("database is not found: %v", dbURI)
// }

// // GetDatabases returns databases
// func (c *Cluster) GetDatabases(ctx context.Context) ([]Database, error) {
// 	var dbs []types.Database
// 	err := addMetadataToRetryableError(ctx, func() error {
// 		proxyClient, err := c.clusterClient.ConnectToProxy(ctx)
// 		if err != nil {
// 			return trace.Wrap(err)
// 		}
// 		defer proxyClient.Close()

// 		dbs, err = proxyClient.FindDatabasesByFilters(ctx, proto.ListResourcesRequest{
// 			Namespace: defaults.Namespace,
// 		})
// 		if err != nil {
// 			return trace.Wrap(err)
// 		}

// 		return nil
// 	})
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	var responseDbs []Database
// 	for _, db := range dbs {
// 		responseDbs = append(responseDbs, Database{
// 			URI:      c.URI.AppendDB(db.GetName()),
// 			Database: db,
// 		})
// 	}

// 	return responseDbs, nil
// }

// // ReissueDBCerts issues new certificates for specific DB access
// func (c *Cluster) ReissueDBCerts(ctx context.Context, user string, db types.Database) error {
// 	// When generating certificate for MongoDB access, database username must
// 	// be encoded into it. This is required to be able to tell which database
// 	// user to authenticate the connection as.
// 	if db.GetProtocol() == libdefaults.ProtocolMongoDB && user == "" {
// 		return trace.BadParameter("please provide the database user name using --db-user flag")
// 	}

// 	err := addMetadataToRetryableError(ctx, func() error {
// 		// Refresh the certs to account for clusterClient.SiteName pointing at a leaf cluster.
// 		err := c.clusterClient.ReissueUserCerts(ctx, client.CertCacheKeep, client.ReissueParams{
// 			RouteToCluster: c.clusterClient.SiteName,
// 			AccessRequests: c.status.ActiveRequests.AccessRequests,
// 		})
// 		if err != nil {
// 			return trace.Wrap(err)
// 		}

// 		// Fetch the certs for the database.
// 		err = c.clusterClient.ReissueUserCerts(ctx, client.CertCacheKeep, client.ReissueParams{
// 			RouteToCluster: c.clusterClient.SiteName,
// 			RouteToDatabase: proto.RouteToDatabase{
// 				ServiceName: db.GetName(),
// 				Protocol:    db.GetProtocol(),
// 				Username:    user,
// 			},
// 			AccessRequests: c.status.ActiveRequests.AccessRequests,
// 		})
// 		if err != nil {
// 			return trace.Wrap(err)
// 		}

// 		return nil
// 	})
// 	if err != nil {
// 		return trace.Wrap(err)
// 	}

// 	// Update the database-specific connection profile file.
// 	err = dbprofile.Add(ctx, c.clusterClient, tlsca.RouteToDatabase{
// 		ServiceName: db.GetName(),
// 		Protocol:    db.GetProtocol(),
// 		Username:    user,
// 	}, c.status)
// 	if err != nil {
// 		return trace.Wrap(err)
// 	}

// 	return nil
// }

// // GetAllowedDatabaseUsers returns allowed users for the given database based on the role set.
// func (c *Cluster) GetAllowedDatabaseUsers(ctx context.Context, dbURI string) ([]string, error) {
// 	var authClient auth.ClientI
// 	var proxyClient *client.ProxyClient
// 	var err error

// 	err = addMetadataToRetryableError(ctx, func() error {
// 		proxyClient, err = c.clusterClient.ConnectToProxy(ctx)
// 		if err != nil {
// 			return trace.Wrap(err)
// 		}

// 		return nil
// 	})
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	defer proxyClient.Close()

// 	authClient, err = proxyClient.ConnectToCluster(ctx, c.clusterClient.SiteName)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	defer authClient.Close()

// 	roleSet, err := services.FetchAllClusterRoles(ctx, authClient, c.status.Roles, c.status.Traits)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	db, err := c.GetDatabase(ctx, dbURI)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	dbUsers := roleSet.EnumerateDatabaseUsers(db)

// 	return dbUsers.Allowed(), nil
// }
