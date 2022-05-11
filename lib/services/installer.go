package services

import (
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

// UnmarshalInstaller unmarshals the installer resource from JSON.
func UnmarshalInstaller(data []byte, opts ...MarshalOption) (types.Installer, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing provision token data")
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var h types.ResourceHeader
	err = utils.FastUnmarshal(data, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !cfg.Expires.IsZero() {
		h.SetExpiry(cfg.Expires)
	}

	var installer types.InstallerV1
	err = utils.FastUnmarshal(data, &installer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &installer, nil
}

// MarshalInstaller marshals the Installer resource to JSON.
func MarshalInstaller(installer types.Installer, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !cfg.PreserveResourceID {
		// avoid modifying the original object
		// to prevent unexpected data races
		copy, ok := installer.(*types.InstallerV1)
		if !ok {
			return nil, trace.BadParameter("unrecognized installer version %T", installer)
		}
		copy.SetResourceID(0)
		installer = copy
	}
	return utils.FastMarshal(installer)

}
