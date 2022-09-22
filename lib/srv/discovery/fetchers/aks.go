/*
Copyright 2022 Gravitational, Inc.

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

package fetchers

import (
	"context"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/strings/slices"
)

type aksFetcher struct {
	AKSFetcherConfig
}

type AKSFetcherConfig struct {
	Client         azure.AKSClient
	Regions        []string
	ResourceGroups []string
	FilterLabels   types.Labels
	Log            logrus.FieldLogger
}

func (c *AKSFetcherConfig) CheckAndSetDefaults() error {
	if c.Client == nil {
		return trace.BadParameter("missing Client field")
	}
	if len(c.Regions) == 0 {
		return trace.BadParameter("missing Regions field")
	}

	if len(c.FilterLabels) == 0 {
		return trace.BadParameter("missing FilterLabels field")
	}

	if c.Log == nil {
		c.Log = logrus.New()
	}
	return nil
}

func NewAKSFetcher(cfg AKSFetcherConfig) (Fetcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &aksFetcher{cfg}, nil
}

func (a *aksFetcher) Get(ctx context.Context) (types.ResourcesWithLabels, error) {

	clusters, err := a.getAKSClusters(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(a.ResourceGroups) == 1 && a.ResourceGroups[0] == types.Wildcard {
		clusters, err = a.Client.ListAll(ctx)

	} else {
		var errs []error
		for _, resourceGroup := range a.ResourceGroups {
			lClusters, lerr := a.Client.ListWithinGroup(ctx, resourceGroup)
			if err != nil {
				errs = append(errs, trace.Wrap(lerr))
				continue
			}
			clusters = append(clusters, lClusters...)
		}
		err = trace.NewAggregate(errs...)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var kubeClusters types.KubeClusters
	for _, cluster := range clusters {
		if !a.isRegionSupported(cluster.Location) {
			a.Log.Debugf("cluster region %q does not match with allowed values", cluster.Location)
			continue
		}
		if match, reason, err := services.MatchLabels(a.FilterLabels, cluster.Tags); err != nil {
			a.Log.WithError(err).Warnf("Unable to match AKS cluster labels against match labels")
			continue
		} else if !match {
			a.Log.Debugf("AKS cluster labels does not match the selector: %s", reason)
			continue
		}

		kubeCluster, err := services.NewKubeClusterFromAzureAKS(cluster)
		if err != nil {
			a.Log.WithError(err).Warnf("Unable create Kubernetes cluster from azure.AKSCluster")
			continue
		}
		kubeClusters = append(kubeClusters, kubeCluster)
	}
	return kubeClusters.AsResources(), nil
}

func (a *aksFetcher) getAKSClusters(ctx context.Context) ([]*azure.AKSCluster, error) {
	var (
		clusters []*azure.AKSCluster
		err      error
	)
	if len(a.ResourceGroups) == 1 && a.ResourceGroups[0] == types.Wildcard {
		clusters, err = a.Client.ListAll(ctx)
	} else {
		var errs []error
		for _, resourceGroup := range a.ResourceGroups {
			lClusters, lerr := a.Client.ListWithinGroup(ctx, resourceGroup)
			if err != nil {
				errs = append(errs, trace.Wrap(lerr))
				continue
			}
			clusters = append(clusters, lClusters...)
		}
		err = trace.NewAggregate(errs...)
	}
	return clusters, trace.Wrap(err)
}

func (a *aksFetcher) isRegionSupported(region string) bool {
	return slices.Contains(a.Regions, types.Wildcard) || slices.Contains(a.Regions, region)
}

func (a *aksFetcher) ResourceType() string {
	return types.KindKubernetesCluster
}
func (a *aksFetcher) Cloud() string {
	return Azure
}
