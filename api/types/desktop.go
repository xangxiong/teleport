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

import "github.com/gravitational/teleport/api/utils"

// WindowsDesktopService represents a Windows desktop service instance.
type WindowsDesktopService interface {
	// ResourceWithLabels provides common resource methods.
	ResourceWithLabels
	ProxiedService
}

// Origin returns the origin value of the resource.
func (s *WindowsDesktopServiceV3) Origin() string {
	return s.Metadata.Origin()
}

// SetOrigin sets the origin value of the resource.
func (s *WindowsDesktopServiceV3) SetOrigin(origin string) {
	s.Metadata.SetOrigin(origin)
}

// GetProxyID returns a list of proxy ids this server is connected to.
func (s *WindowsDesktopServiceV3) GetProxyIDs() []string {
	return s.Spec.ProxyIDs
}

// SetProxyID sets the proxy ids this server is connected to.
func (s *WindowsDesktopServiceV3) SetProxyIDs(proxyIDs []string) {
	s.Spec.ProxyIDs = proxyIDs
}

// GetAllLabels returns the resources labels.
func (s *WindowsDesktopServiceV3) GetAllLabels() map[string]string {
	return s.Metadata.Labels
}

// GetStaticLabels returns the windows desktop static labels.
func (s *WindowsDesktopServiceV3) GetStaticLabels() map[string]string {
	return s.Metadata.Labels
}

// SetStaticLabels sets the windows desktop static labels.
func (s *WindowsDesktopServiceV3) SetStaticLabels(sl map[string]string) {
	s.Metadata.Labels = sl
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (s *WindowsDesktopServiceV3) MatchSearch(values []string) bool {
	return MatchSearch(nil, values, nil)
}

// WindowsDesktop represents a Windows desktop host.
type WindowsDesktop interface {
	// ResourceWithLabels provides common resource methods.
	ResourceWithLabels
}

// GetAddr returns the network address of this host.
func (d *WindowsDesktopV3) GetAddr() string {
	return d.Spec.Addr
}

// GetAllLabels returns combined static and dynamic labels.
func (d *WindowsDesktopV3) GetAllLabels() map[string]string {
	// TODO(zmb3): add dynamic labels when running in agent mode
	return CombineLabels(d.Metadata.Labels, nil)
}

// GetStaticLabels returns the windows desktop static labels.
func (d *WindowsDesktopV3) GetStaticLabels() map[string]string {
	return d.Metadata.Labels
}

// SetStaticLabels sets the windows desktop static labels.
func (d *WindowsDesktopV3) SetStaticLabels(sl map[string]string) {
	d.Metadata.Labels = sl
}

// Origin returns the origin value of the resource.
func (d *WindowsDesktopV3) Origin() string {
	return d.Metadata.Labels[OriginLabel]
}

// SetOrigin sets the origin value of the resource.
func (d *WindowsDesktopV3) SetOrigin(o string) {
	d.Metadata.Labels[OriginLabel] = o
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (d *WindowsDesktopV3) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(d.GetAllLabels()), d.GetName(), d.GetAddr())
	return MatchSearch(fieldVals, values, nil)
}
