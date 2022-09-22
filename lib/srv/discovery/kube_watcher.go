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

package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
)

const (
	concurrencyLimit = 5
)

func (s *Server) startKubeWatchers() error {
	if len(s.kubeFetchers) == 0 {
		return nil
	}
	var (
		kubeResources types.ResourcesWithLabels
		mu            sync.Mutex
		t             = time.NewTicker(time.Minute)
	)
	watcher, err := services.NewReconciler(
		services.ReconcilerConfig{
			Matcher: func(_ types.ResourceWithLabels) bool { return true },
			GetCurrentResources: func() types.ResourcesWithLabelsMap {
				kcs, err := s.AccessPoint.GetKubernetesClusters(s.ctx)
				if err != nil {
					s.Log.WithError(err).Warnf("unable to get kubernetes clusters from cache")
					return nil
				}

				// filter only discover clusters.
				var kubeClusters types.KubeClusters
				for _, kc := range kcs {
					if kc.Origin() != types.OriginCloud {
						continue
					}
					kubeClusters = append(kubeClusters, kc)
				}

				return kubeClusters.AsResources().ToMap()
			},
			GetNewResources: func() types.ResourcesWithLabelsMap {
				mu.Lock()
				defer mu.Unlock()
				return kubeResources.ToMap()
			},
			Log:      s.Log,
			OnCreate: s.onKubeCreate,
			OnUpdate: s.onKubeUpdate,
			OnDelete: s.onKubeDelete,
		},
	)
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {

		for {

			errGroup, errgCtx := errgroup.WithContext(s.ctx)
			errGroup.SetLimit(concurrencyLimit)
			for _, fetcher := range s.kubeFetchers {
				lFetcher := fetcher

				errGroup.Go(func() error {
					resources, err := lFetcher.Get(errgCtx)
					if err != nil {
						s.Log.WithError(err).Warnf("unable to fetch resources for %s at %s", lFetcher.ResourceType(), lFetcher.Cloud())
						// never return the error otherwise it will impact other watchers.
						return nil
					}
					mu.Lock()
					kubeResources = append(kubeResources, resources...)
					mu.Unlock()
					return nil
				})
			}
			// error is discarded because we must run all fetchers until the end.
			_ = errGroup.Wait()

			if err := watcher.Reconcile(s.ctx); err != nil {
				s.Log.WithError(err).Warnf("unable to reconcile resources")
			}

			select {
			case <-t.C:
			case <-s.ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (s *Server) onKubeCreate(ctx context.Context, rwl types.ResourceWithLabels) error {
	kubeCluster, ok := rwl.(types.KubeCluster)
	if !ok {
		return trace.BadParameter("invalid type received; expected types.KubeCluster, received %T", kubeCluster)
	}
	s.Log.Debugf("creating kube_cluster %s", kubeCluster.GetName())
	return trace.Wrap(s.AccessPoint.CreateKubernetesCluster(ctx, kubeCluster))
}

func (s *Server) onKubeUpdate(ctx context.Context, rwl types.ResourceWithLabels) error {
	kubeCluster, ok := rwl.(types.KubeCluster)
	if !ok {
		return trace.BadParameter("invalid type received; expected types.KubeCluster, received %T", kubeCluster)
	}
	s.Log.Debugf("updating kube_cluster %s", kubeCluster.GetName())
	return trace.Wrap(s.AccessPoint.UpdateKubernetesCluster(ctx, kubeCluster))
}

func (s *Server) onKubeDelete(ctx context.Context, rwl types.ResourceWithLabels) error {
	kubeCluster, ok := rwl.(types.KubeCluster)
	if !ok {
		return trace.BadParameter("invalid type received; expected types.KubeCluster, received %T", kubeCluster)
	}
	s.Log.Debugf("deleting kube_cluster %s", kubeCluster.GetName())
	return trace.Wrap(s.AccessPoint.DeleteKubernetesCluster(ctx, kubeCluster.GetName()))
}
