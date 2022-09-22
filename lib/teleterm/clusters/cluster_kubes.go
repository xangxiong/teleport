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

import (
	"context"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"

	"github.com/gravitational/trace"
)

// Kube describes kubernetes service
type Kube struct {
	// URI is the kube URI
	URI uri.ResourceURI

	KubernetesCluster types.KubeCluster
}

// GetKubes returns kube services
func (c *Cluster) GetKubes(ctx context.Context) ([]Kube, error) {
	var authClient auth.ClientI
	var proxyClient *client.ProxyClient
	var err error

	err = addMetadataToRetryableError(ctx, func() error {
		proxyClient, err = c.clusterClient.ConnectToProxy(ctx)
		if err != nil {
			return trace.Wrap(err)
		}

		return nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer proxyClient.Close()

	authClient, err = proxyClient.ConnectToCluster(ctx, c.clusterClient.SiteName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	defer authClient.Close()

	servers, err := authClient.GetKubernetesServers(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	kubeMap := map[string]Kube{}
	for _, server := range servers {
		kube := server.GetCluster()
		if kube == nil {
			continue
		}

		kubeMap[kube.GetName()] = Kube{
			URI:               c.URI.AppendKube(kube.GetName()),
			KubernetesCluster: kube,
		}

	}

	kubes := make([]Kube, 0, len(kubeMap))
	for _, value := range kubeMap {
		kubes = append(kubes, value)
	}

	return kubes, nil
}
