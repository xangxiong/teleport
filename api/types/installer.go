package types

import "time"

// Installer is an installer script rseource
type Installer interface {
	Resource

	GetScript() string
	SetScript(string)

	String() string
}

func NewInstallerV1(meta Metadata, spec InstallerSpecV1) (*InstallerV1, error) {
	installer := &InstallerV1{
		Metadata: meta,
		Spec:     spec,
	}
	return installer, nil
}

// CheckAndSetDefaults implements Installer
func (InstallerV1) CheckAndSetDefaults() error {
	return nil
}

// GetVersion returns resource version.
func (c *InstallerV1) GetVersion() string {
	return c.Version
}

// GetName returns the name of the resource.
func (c *InstallerV1) GetName() string {
	return c.Metadata.Name
}

// SetName sets the name of the resource.
func (c *InstallerV1) SetName(e string) {
	c.Metadata.Name = e
}

// SetExpiry sets expiry time for the object.
func (c *InstallerV1) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// Expiry returns object expiry setting.
func (c *InstallerV1) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// GetMetadata returns object metadata.
func (c *InstallerV1) GetMetadata() Metadata {
	return c.Metadata
}

// GetResourceID returns resource ID.
func (c *InstallerV1) GetResourceID() int64 {
	return c.Metadata.ID
}

// SetResourceID sets resource ID.
func (c *InstallerV1) SetResourceID(id int64) {
	c.Metadata.ID = id
}

// GetKind returns resource kind.
func (c *InstallerV1) GetKind() string {
	return c.Kind
}

// GetSubKind returns resource subkind.
func (c *InstallerV1) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind.
func (c *InstallerV1) SetSubKind(sk string) {
	c.SubKind = sk
}

func (i *InstallerV1) GetScript() string {
	return i.Spec.Script
}

func (i *InstallerV1) SetScript(s string) {
	i.Spec.Script = s
}
