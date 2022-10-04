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

package types

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/api/utils"

	"github.com/gogo/protobuf/proto"
	"github.com/gravitational/trace"
)

// Database represents a database proxied by a database server.
type Database interface {
	// ResourceWithLabels provides common resource methods.
	ResourceWithLabels
	// String returns string representation of the database.
	String() string
	// GetDescription returns the database description.
	GetDescription() string
	// GetType returns the database authentication type: self-hosted, RDS, Redshift or Cloud SQL.
	GetType() string
	// Copy returns a copy of this database resource.
	Copy() *DatabaseV3
}

// NewDatabaseV3 creates a new database resource.
func NewDatabaseV3(meta Metadata, spec DatabaseSpecV3) (*DatabaseV3, error) {
	database := &DatabaseV3{
		Metadata: meta,
		Spec:     spec,
	}
	if err := database.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return database, nil
}

// GetVersion returns the database resource version.
func (d *DatabaseV3) GetVersion() string {
	return d.Version
}

// GetKind returns the database resource kind.
func (d *DatabaseV3) GetKind() string {
	return d.Kind
}

// GetSubKind returns the database resource subkind.
func (d *DatabaseV3) GetSubKind() string {
	return d.SubKind
}

// SetSubKind sets the database resource subkind.
func (d *DatabaseV3) SetSubKind(sk string) {
	d.SubKind = sk
}

// GetResourceID returns the database resource ID.
func (d *DatabaseV3) GetResourceID() int64 {
	return d.Metadata.ID
}

// SetResourceID sets the database resource ID.
func (d *DatabaseV3) SetResourceID(id int64) {
	d.Metadata.ID = id
}

// GetMetadata returns the database resource metadata.
func (d *DatabaseV3) GetMetadata() Metadata {
	return d.Metadata
}

// Origin returns the origin value of the resource.
func (d *DatabaseV3) Origin() string {
	return d.Metadata.Origin()
}

// SetOrigin sets the origin value of the resource.
func (d *DatabaseV3) SetOrigin(origin string) {
	d.Metadata.SetOrigin(origin)
}

// SetExpiry sets the database resource expiration time.
func (d *DatabaseV3) SetExpiry(expiry time.Time) {
	d.Metadata.SetExpiry(expiry)
}

// Expiry returns the database resource expiration time.
func (d *DatabaseV3) Expiry() time.Time {
	return d.Metadata.Expiry()
}

// GetName returns the database resource name.
func (d *DatabaseV3) GetName() string {
	return d.Metadata.Name
}

// SetName sets the database resource name.
func (d *DatabaseV3) SetName(name string) {
	d.Metadata.Name = name
}

// GetStaticLabels returns the database static labels.
func (d *DatabaseV3) GetStaticLabels() map[string]string {
	return d.Metadata.Labels
}

// SetStaticLabels sets the database static labels.
func (d *DatabaseV3) SetStaticLabels(sl map[string]string) {
	d.Metadata.Labels = sl
}

// GetAllLabels returns the database combined static and dynamic labels.
func (d *DatabaseV3) GetAllLabels() map[string]string {
	return CombineLabels(d.Metadata.Labels, d.Spec.DynamicLabels)
}

// LabelsString returns all database labels as a string.
func (d *DatabaseV3) LabelsString() string {
	return LabelsAsString(d.Metadata.Labels, d.Spec.DynamicLabels)
}

// GetDescription returns the database description.
func (d *DatabaseV3) GetDescription() string {
	return d.Metadata.Description
}

// GetProtocol returns the database protocol.
func (d *DatabaseV3) GetProtocol() string {
	return d.Spec.Protocol
}

// GetType returns the database type.
func (d *DatabaseV3) GetType() string {
	return DatabaseTypeSelfHosted
}

// String returns the database string representation.
func (d *DatabaseV3) String() string {
	return fmt.Sprintf("Database(Name=%v, Type=%v, Labels=%v)",
		d.GetName(), d.GetType(), d.GetAllLabels())
}

// Copy returns a copy of this database resource.
func (d *DatabaseV3) Copy() *DatabaseV3 {
	return proto.Clone(d).(*DatabaseV3)
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (d *DatabaseV3) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(d.GetAllLabels()), d.GetName(), d.GetDescription(), d.GetProtocol(), d.GetType())

	var custom func(string) bool
	return MatchSearch(fieldVals, values, custom)
}

// setStaticFields sets static resource header and metadata fields.
func (d *DatabaseV3) setStaticFields() {
	d.Kind = KindDatabase
	d.Version = V3
}

// CheckAndSetDefaults checks and sets default values for any missing fields.
func (d *DatabaseV3) CheckAndSetDefaults() error {
	d.setStaticFields()
	if err := d.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	for key := range d.Spec.DynamicLabels {
		if !IsValidLabelKey(key) {
			return trace.BadParameter("database %q invalid label key: %q", d.GetName(), key)
		}
	}
	if d.Spec.Protocol == "" {
		return trace.BadParameter("database %q protocol is empty", d.GetName())
	}
	if d.Spec.URI == "" {
		return trace.BadParameter("database %q URI is empty", d.GetName())
	}
	if d.Spec.MySQL.ServerVersion != "" && d.Spec.Protocol != "mysql" {
		return trace.BadParameter("MySQL ServerVersion can be only set for MySQL database")
	}
	return nil
}

// GetIAMPolicy returns AWS IAM policy for this database.
func (d *DatabaseV3) GetIAMPolicy() (string, error) {
	return "", nil
}

// GetIAMAction returns AWS IAM action needed to connect to the database.
func (d *DatabaseV3) GetIAMAction() string {
	return ""
}

// GetIAMResources returns AWS IAM resources that provide access to the database.
func (d *DatabaseV3) GetIAMResources() []string {
	return nil
}

// GetSecretStore returns secret store configurations.
func (d *DatabaseV3) GetSecretStore() SecretStore {
	return d.Spec.AWS.SecretStore
}

// GetManagedUsers returns a list of database users that are managed by Teleport.
func (d *DatabaseV3) GetManagedUsers() []string {
	return d.Status.ManagedUsers
}

// SetManagedUsers sets a list of database users that are managed by Teleport.
func (d *DatabaseV3) SetManagedUsers(users []string) {
	d.Status.ManagedUsers = users
}

const (
	// DatabaseTypeSelfHosted is the self-hosted type of database.
	DatabaseTypeSelfHosted = "self-hosted"
)

// DeduplicateDatabases deduplicates databases by name.
func DeduplicateDatabases(databases []Database) (result []Database) {
	seen := make(map[string]struct{})
	for _, database := range databases {
		if _, ok := seen[database.GetName()]; ok {
			continue
		}
		seen[database.GetName()] = struct{}{}
		result = append(result, database)
	}
	return result
}

// Databases is a list of database resources.
type Databases []Database

// ToMap returns these databases as a map keyed by database name.
func (d Databases) ToMap() map[string]Database {
	m := make(map[string]Database)
	for _, database := range d {
		m[database.GetName()] = database
	}
	return m
}

// AsResources returns these databases as resources with labels.
func (d Databases) AsResources() (resources ResourcesWithLabels) {
	for _, database := range d {
		resources = append(resources, database)
	}
	return resources
}

// Len returns the slice length.
func (d Databases) Len() int { return len(d) }

// Less compares databases by name.
func (d Databases) Less(i, j int) bool { return d[i].GetName() < d[j].GetName() }

// Swap swaps two databases.
func (d Databases) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
