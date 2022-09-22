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

package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	armazcore "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	rbacv1 "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes"
	authztypes "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type AKSAccessConfig uint8

const (
	AzureRBAC AKSAccessConfig = iota
	AzureAD
	LocalAccounts
)

type AKSCluster struct {
	Name           string
	GroupName      string
	TenantID       string
	Location       string
	SubscriptionID string
	Tags           map[string]string
	Properties     AKSClusterProperties
}

type AKSClusterProperties struct {
	AccessConfig  AKSAccessConfig
	LocalAccounts bool
	ClusterState  string
}

// ARMAKS is an interface for armcontainerservice.ManagedClustersClient.
type ARMAKS interface {
	BeginRunCommand(ctx context.Context, resourceGroupName string, resourceName string, requestPayload armcontainerservice.RunCommandRequest, options *armcontainerservice.ManagedClustersClientBeginRunCommandOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientRunCommandResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientGetOptions) (armcontainerservice.ManagedClustersClientGetResponse, error)
	GetCommandResult(ctx context.Context, resourceGroupName string, resourceName string, commandID string, options *armcontainerservice.ManagedClustersClientGetCommandResultOptions) (armcontainerservice.ManagedClustersClientGetCommandResultResponse, error)
	ListClusterAdminCredentials(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientListClusterAdminCredentialsOptions) (armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse, error)
	ListClusterUserCredentials(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientListClusterUserCredentialsOptions) (armcontainerservice.ManagedClustersClientListClusterUserCredentialsResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcontainerservice.ManagedClustersClientListByResourceGroupOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListByResourceGroupResponse]
	NewListPager(options *armcontainerservice.ManagedClustersClientListOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListResponse]
}

var _ ARMAKS = (*armcontainerservice.ManagedClustersClient)(nil)

// ImpersonationPermissionsChecker describes a function that can be used to check
// for the required impersonation permissions on a Kubernetes cluster. Return nil
// to indicate success.
type ImpersonationPermissionsChecker func(ctx context.Context, clusterName string,
	sarClient authztypes.SelfSubjectAccessReviewInterface) error

// AzureIdentityFunction is a function signature used to setup azure credentials.
// This is used to generate special credentials with cluster TentantID to retrieve
// access tokens.
type AzureIdentityFunction func(options *azidentity.DefaultAzureCredentialOptions) (*azidentity.DefaultAzureCredential, error)

// ClusterCredentialsConfig are the required parameters for generating cluster credentials.
type ClusterCredentialsConfig struct {
	// ResourceGroup is the AKS cluster resource group.
	ResourceGroup string
	// ResourceName is the AKS cluster name.
	ResourceName string
	// TenantID is the AKS cluster tenant id.
	TenantID string
	// ImpersonationPermissionsChecker is checker function that validates if access
	// was granted.
	ImpersonationPermissionsChecker ImpersonationPermissionsChecker
}

// CheckAndSetDefaults checks for required parameters.
func (c ClusterCredentialsConfig) CheckAndSetDefaults() error {
	if len(c.ResourceGroup) == 0 {
		return trace.BadParameter("invalid ResourceGroup field")
	}
	if len(c.ResourceName) == 0 {
		return trace.BadParameter("invalid ResourceName field")
	}
	if c.ImpersonationPermissionsChecker == nil {
		return trace.BadParameter("invalid ImpersonationPermissionsChecker field")
	}
	return nil
}

// AKSClient is the Azure client to interact with AKS.
type AKSClient interface {
	// ListAll returns all AKSClusters the user has access to.
	ListAll(ctx context.Context) ([]*AKSCluster, error)
	// ListAll returns all AKSClusters the user has access to within the resource group.
	ListWithinGroup(ctx context.Context, group string) ([]*AKSCluster, error)
	// ClusterCredentials returns the credentials for accessing the desired AKS cluster.
	// if agent access has not yet been configured, this function will attempt to configure it
	// using administrator credentials `ListClusterAdminCredentials`` or by running a command `BeginRunCommand`.
	// If the access setup is not successful, then an error is returned.
	ClusterCredentials(ctx context.Context, cfg ClusterCredentialsConfig) (*rest.Config, time.Time, error)
}

// aKSClient wraps the ARMAKS API and satisfies AKSClient.
type aKSClient struct {
	api        ARMAKS
	azIdentity AzureIdentityFunction
}

// NewAKSClustersClient returns a client for Azure AKS clusters.
func NewAKSClustersClient(api ARMAKS, azIdentity AzureIdentityFunction) AKSClient {
	if azIdentity == nil {
		azIdentity = azidentity.NewDefaultAzureCredential
	}
	return &aKSClient{api: api, azIdentity: azIdentity}
}

// get returns AKSCluster information for a single AKS cluster.
func (c *aKSClient) get(ctx context.Context, group, name string) (*AKSCluster, error) {
	res, err := c.api.Get(ctx, group, name, nil)
	if err != nil {
		return nil, trace.Wrap(ConvertResponseError(err))
	}
	return AKSClusterFromManagedCluster(&res.ManagedCluster), nil
}

func (c *aKSClient) ListAll(ctx context.Context) ([]*AKSCluster, error) {
	var servers []*AKSCluster
	options := &armcontainerservice.ManagedClustersClientListOptions{}
	pager := c.api.NewListPager(options)
	for pageNum := 0; pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(ConvertResponseError(err))
		}
		for _, s := range page.Value {
			servers = append(servers, AKSClusterFromManagedCluster(s))
		}
	}
	return servers, nil
}

func (c *aKSClient) ListWithinGroup(ctx context.Context, group string) ([]*AKSCluster, error) {
	var servers []*AKSCluster
	options := &armcontainerservice.ManagedClustersClientListByResourceGroupOptions{}
	pager := c.api.NewListByResourceGroupPager(group, options)
	for pageNum := 0; pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(ConvertResponseError(err))
		}
		for _, s := range page.Value {
			servers = append(servers, AKSClusterFromManagedCluster(s))
		}
	}
	return servers, nil
}

type ClientConfig struct {
	ResourceGroup string
	Name          string
	TenantID      string
}

func (c *aKSClient) ClusterCredentials(ctx context.Context, cfg ClusterCredentialsConfig) (*rest.Config, time.Time, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}
	// get cluster auth information
	clusterDetails, err := c.get(ctx, cfg.ResourceGroup, cfg.ResourceName)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(ConvertResponseError(err))
	}

	switch clusterDetails.Properties.AccessConfig {
	case AzureRBAC:
		// In this mode, Authentication happens via AD users and Authorization is granted by AzureRBAC.
		cfg, expiresOn, err := c.getAzureRBACCredentials(ctx, cfg)
		return cfg, expiresOn, trace.Wrap(err)
	case AzureAD:
		// In this mode, Authentication happens via AD users and Authorization is granted by Kubernetes RBAC.
		cfg, expiresOn, err := c.getAzureADCredentials(ctx, cfg)
		return cfg, expiresOn, trace.Wrap(err)
	case LocalAccounts:
		// In this mode, Authentication is granted by provisioned static accounts accessible via
		// ListClusterUserCredentials
		cfg, err := c.getUserCredentials(ctx, cfg)
		if err != nil {
			return nil, time.Time{}, trace.Wrap(err)
		}
		// make sure the credentials are not exec based.
		cfg, err = checkIfAuthMethodIsUnSupported(cfg)
		// the access credentials are static and are only changed if there is a change in the cluster CA, however to prevent this we will refresh the credentials
		return cfg, time.Now().Add(1 * time.Hour), trace.Wrap(err)
	default:
		return nil, time.Time{}, trace.BadParameter("unsuported AKS authentication mode %s", clusterDetails.Properties.AccessConfig)
	}

}

// getAzureRBACCredentials generates a config to access the cluster.
// When AzureRBAC is enabled, the authentication happens with a BearerToken and the principal role
// grants has the access rules to the cluster. If checkPermissions fails we cannot do anything.
func (c *aKSClient) getAzureRBACCredentials(ctx context.Context, cluster ClusterCredentialsConfig) (*rest.Config, time.Time, error) {
	cfg, err := c.getUserCredentials(ctx, cluster)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}
	expiresOn, err := c.getAzureToken(ctx, cluster.TenantID, cfg)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}

	if err := c.checkAccessPermissions(ctx, cfg, cluster); err != nil {
		return nil, time.Time{}, trace.WrapWithMessage(err, `Azure RBAC rules have not been configured for the agent. 
		Please check that you have configured correctly.`)
	}

	return cfg, expiresOn, nil
}

// getUserCredentials gets the user credentials by calling `ListClusterUserCredentials` method
// and parsing the kubeconfig returned.
func (c *aKSClient) getUserCredentials(ctx context.Context, cfg ClusterCredentialsConfig) (*rest.Config, error) {
	options := &armcontainerservice.ManagedClustersClientListClusterUserCredentialsOptions{
		// format is only applied if AD is enabled but we can force the request with it.
		Format: valToPtr(armcontainerservice.FormatExec),
	}
	res, err := c.api.ListClusterUserCredentials(ctx, cfg.ResourceGroup, cfg.ResourceName, options)
	if err != nil {
		return nil, trace.Wrap(ConvertResponseError(err))
	}

	result, err := c.getRestConfigFromKubeconfigs(res.Kubeconfigs)
	return result, trace.Wrap(err)

}

// getAzureADCredentials gets the client configuration and checks if Kubernetes RBAC is configured.
func (c *aKSClient) getAzureADCredentials(ctx context.Context, cluster ClusterCredentialsConfig) (*rest.Config, time.Time, error) {
	// getUserCredentials is used to extract the cluster CA and API endpoint.
	cfg, err := c.getUserCredentials(ctx, cluster)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}
	expiresOn, err := c.getAzureToken(ctx, cluster.TenantID, cfg)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}

	// checks if agent already has access to the cluster
	if err := c.checkAccessPermissions(ctx, cfg, cluster); err == nil {
		// access to the cluster was already granted!
		return cfg, expiresOn, nil
	}

	// parse the azure JWT token to extract the first groupID the principal belongs to.
	groupID, err := extractGroupFromAzure(cfg.BearerToken)
	if err != nil {
		return nil, time.Time{}, trace.Wrap(err)
	}

	var (
		adminCredentialsErr error
		runCMDErr           error
	)

	// calls the ListClusterAdminCrdentials endpoint to return the admin static credentials.
	adminCfg, err := c.getAdminCredentials(ctx, cluster.ResourceGroup, cluster.ResourceName)
	switch {
	case err == nil:
		// given the admin credentials, the agent will try to create the ClusterRole and
		// ClusterRoleBinding objects in the AKS cluster.
		if adminCredentialsErr = c.grantAccessWithAdminCredentials(ctx, adminCfg, groupID); adminCredentialsErr == nil {
			// checks if agent already has access to the cluster
			if err := c.checkAccessPermissions(ctx, cfg, cluster); err == nil {
				// access to the cluster was already granted!
				return cfg, expiresOn, nil
			}
		}
		adminCredentialsErr = trace.WrapWithMessage(adminCredentialsErr, `Tried to grant access to %s/%s using aks.ListClusterAdminCredentials`, cluster.ResourceGroup, cluster.ResourceName)
		// if the creation failed, then the agent will try to run a command to create them.
		fallthrough
	case err != nil:
		if runCMDErr = c.grantAccessWithCommand(ctx, cluster.ResourceGroup, cluster.ResourceName, groupID); runCMDErr != nil {
			return nil, time.Time{}, trace.Wrap(err)
		}
		if err := c.checkAccessPermissions(ctx, cfg, cluster); err == nil {
			// access to the cluster was already granted!
			return cfg, expiresOn, nil
		}
		runCMDErr = trace.WrapWithMessage(runCMDErr, `Tried to grant access to %s/%s using aks.BeginRunCommand`, cluster.ResourceGroup, cluster.ResourceName)
		return nil, time.Time{}, trace.WrapWithMessage(trace.NewAggregate(adminCredentialsErr, runCMDErr), `Cannot grant access to %s/%s AKS cluster`, cluster.ResourceGroup, cluster.ResourceName)
	}

	return nil, time.Time{}, trace.NotImplemented("code shouldn't reach")
}

// getAdminCredentials returns the cluster admin credentials by calling ListClusterAdminCredentials method.
// This function also validates if the credentials are not exec based.
func (c *aKSClient) getAdminCredentials(ctx context.Context, group, name string) (*rest.Config, error) {
	options := &armcontainerservice.ManagedClustersClientListClusterAdminCredentialsOptions{}
	res, err := c.api.ListClusterAdminCredentials(ctx, group, name, options)
	if err != nil {
		return nil, trace.Wrap(ConvertResponseError(err))
	}

	result, err := c.getRestConfigFromKubeconfigs(res.Kubeconfigs)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	result, err = checkIfAuthMethodIsUnSupported(result)
	return result, trace.Wrap(err)

}

// getRestConfigFromKubeconfigs parses the first kubeConfig returned by ListClusterAdminCredentials and
// ListClusterUserCredentials methods.
func (c *aKSClient) getRestConfigFromKubeconfigs(kubes []*armcontainerservice.CredentialResult) (*rest.Config, error) {
	if len(kubes) == 0 {
		return nil, trace.NotFound("no valid kubeconfig returned")
	}
	config, err := clientcmd.Load(kubes[0].Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	kubeRestConfig, err := clientcmd.NewDefaultClientConfig(*config, nil).ClientConfig()
	return kubeRestConfig, trace.Wrap(err)
}

// checkAccessPermissions checks if the agent has the required permissions to operate.
func (a *aKSClient) checkAccessPermissions(ctx context.Context, clientCfg *rest.Config, cluster ClusterCredentialsConfig) error {
	client, err := kubernetes.NewForConfig(clientCfg)
	if err != nil {
		return trace.Wrap(err, "failed to generate Kubernetes client for cluster")
	}
	sarClient := client.AuthorizationV1().SelfSubjectAccessReviews()
	return trace.Wrap(cluster.ImpersonationPermissionsChecker(ctx, cluster.ResourceName, sarClient))
}

// getAzureToken generates an authentication token for clusters with AD enabled.
func (a *aKSClient) getAzureToken(ctx context.Context, tentantID string, clientCfg *rest.Config) (time.Time, error) {
	const (
		azureManagedClusterScope = "6dae42f8-4368-4678-94ff-3960e28e3630"
	)
	cred, err := a.azIdentity(&azidentity.DefaultAzureCredentialOptions{
		TenantID: tentantID,
	})
	if err != nil {
		return time.Time{}, trace.Wrap(ConvertResponseError(err))
	}

	cliAccessToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		// azureManagedClusterScope is a fixed scope that identifies azure AKS managed clusters.
		Scopes: []string{azureManagedClusterScope},
	},
	)
	if err != nil {
		return time.Time{}, trace.Wrap(ConvertResponseError(err))
	}
	// reset the old exec provider credentials
	clientCfg.ExecProvider = nil
	clientCfg.BearerToken = cliAccessToken.Token

	return cliAccessToken.ExpiresOn, nil
}

// grantAccessWithAdminCredentials tries to create the ClusterRole and ClusterRoleBinding into the AKS cluster
// using admin credentials.
func (c *aKSClient) grantAccessWithAdminCredentials(ctx context.Context, adminCfg *rest.Config, groupID string) error {
	client, err := kubernetes.NewForConfig(adminCfg)
	if err != nil {
		return trace.Wrap(err, "failed to generate Kubernetes client for cluster")
	}

	if err := c.createClusterRoleWithAdminCredentials(ctx, client); err != nil {
		return trace.Wrap(err)
	}

	err = c.createClusterRoleBindingWithAdminCredentials(ctx, client, groupID)
	return trace.Wrap(err)

}

// createClusterRoleWithAdminCredentials tries to create the ClusterRole using admin credentials.
func (c *aKSClient) createClusterRoleWithAdminCredentials(ctx context.Context, client *kubernetes.Clientset) error {
	clusterRole := &v1.ClusterRole{}

	if err := yaml.Unmarshal([]byte(clusterRoleTemplate), clusterRole); err != nil {
		return trace.Wrap(err)
	}

	applyRole, err := rbacv1.ExtractClusterRole(clusterRole, resourceOwner)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = client.RbacV1().ClusterRoles().Apply(ctx, applyRole, metav1.ApplyOptions{})
	return trace.Wrap(err)

}

// createClusterRoleBindingWithAdminCredentials tries to create the ClusterRoleBinding using admin credentials
// and maps it into the principal group.
func (c *aKSClient) createClusterRoleBindingWithAdminCredentials(ctx context.Context, client *kubernetes.Clientset, groupID string) error {
	clusterRoleBinding := &v1.ClusterRoleBinding{}

	if err := yaml.Unmarshal([]byte(clusterRoleTemplate), clusterRoleBinding); err != nil {
		return trace.Wrap(err)
	}

	clusterRoleBinding.Subjects[0].Name = groupID

	applyRoleBinding, err := rbacv1.ExtractClusterRoleBinding(clusterRoleBinding, resourceOwner)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = client.RbacV1().ClusterRoleBindings().Apply(ctx, applyRoleBinding, metav1.ApplyOptions{})
	return trace.Wrap(err)
}

// grantAccessWithAdminCredentials tries to create the ClusterRole and ClusterRoleBinding into the AKS cluster
// using remote kubectl command.
func (c *aKSClient) grantAccessWithCommand(ctx context.Context, resourceGroupName, resourceName, groupID string) error {
	cmd, err := c.api.BeginRunCommand(ctx, resourceGroupName, resourceName, armcontainerservice.RunCommandRequest{
		Command: valToPtr(fmt.Sprintf("%s\n---\n%s", clusterRoleTemplate, strings.ReplaceAll(clusterRoleBindingTemplate, "{group_name}", groupID))),
	}, &armcontainerservice.ManagedClustersClientBeginRunCommandOptions{})
	if err != nil {
		return trace.Wrap(ConvertResponseError(err))
	}
	_, err = cmd.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: time.Second})
	return trace.Wrap(ConvertResponseError(err))
}

// extractGroupFromAzure extracts the first group id in the Azure Bearer Token.
func extractGroupFromAzure(token string) (string, error) {
	p := jwt.NewParser()
	claims := &azureGroupClaims{}
	// We are not intered in validating the token since
	// we generated it from Azure SDK.
	_, _, err := p.ParseUnverified(token, claims)
	if err != nil {
		return "", trace.Wrap(err)
	}
	// ParseUnverified already validates that len(claims.Groups)>0
	return claims.Groups[0], nil
}

// checkIfAuthMethodIsUnSupported checks if the credentials are not exec based.
func checkIfAuthMethodIsUnSupported(cfg *rest.Config) (*rest.Config, error) {
	if cfg.ExecProvider != nil {
		return nil, trace.BadParameter("exec auth format not supported")
	}
	return cfg, nil
}

// AKSClusterFromManagedCluster converts an Azure armcontainerservice.ManagedCluster into AKSCluster.
func AKSClusterFromManagedCluster(cluster *armcontainerservice.ManagedCluster) *AKSCluster {
	result := &AKSCluster{
		Name:     stringVal(cluster.Name),
		Location: stringVal(cluster.Location),
		Tags:     convertTags(cluster.Tags),
	}
	if cluster.Identity != nil {
		result.TenantID = stringVal(cluster.Identity.TenantID)
	}
	if subID, groupName, err := extractSubscriptionAndGroupName(cluster.ID); err == nil {
		result.GroupName, result.SubscriptionID = groupName, subID
	}

	if cluster.Properties != nil {
		if cluster.Properties.AADProfile != nil && ptrToVal(cluster.Properties.AADProfile.EnableAzureRBAC) {
			result.Properties = AKSClusterProperties{
				AccessConfig: AzureRBAC,
				ClusterState: stringVal(cluster.Properties.ProvisioningState),
			}
		} else if cluster.Properties.AADProfile != nil {
			result.Properties = AKSClusterProperties{
				AccessConfig:  AzureAD,
				LocalAccounts: !ptrToVal(cluster.Properties.DisableLocalAccounts),
				ClusterState:  stringVal(cluster.Properties.ProvisioningState),
			}
		} else {
			result.Properties = AKSClusterProperties{
				AccessConfig:  LocalAccounts,
				LocalAccounts: true,
				ClusterState:  stringVal(cluster.Properties.ProvisioningState),
			}
		}

	}
	return result
}

// IsAvailable returns whether the Azure DBServer is available.
func (s *AKSCluster) IsAvailable() bool {
	switch s.Properties.ClusterState {
	case "Succeeded", "Updating":
		return true
		// FIXME: check this available
	case "Inaccessible", "Dropping", "Disabled":
		return false
	default:
		log.Warnf("Unknown cluster state: %q. Assuming Azure AKS cluster %q is available.",
			s.Properties.ClusterState,
			s.Name,
		)
		return true
	}
}

func ptrToVal[T any](s *T) T {
	var result T
	if s != nil {
		result = *s
	}
	return result
}

func valToPtr[T any](s T) *T {
	return &s
}

// extractGroupName extracts the group name from resource id.
// ids are in the form of:
// /subscriptions/{subscription_id}/resourcegroups/{resource_group}/providers/Microsoft.ContainerService/managedClusters/{name}
func extractSubscriptionAndGroupName(id *string) (string, string, error) {
	if id == nil {
		return "", "", trace.BadParameter("invalid resource_id provided")
	}
	resource, err := armazcore.ParseResourceID(*id)
	if err != nil {
		return "", "", trace.Wrap(err)
	}
	return resource.SubscriptionID, resource.ResourceGroupName, nil
}

// azureGroupClaims the configuration settings of the Azure Active Directory allowed principals.
type azureGroupClaims struct {
	// Groups - The list of the allowed groups.
	Groups []string `json:"groups,omitempty"`
}

func (c *azureGroupClaims) Valid() error {
	if len(c.Groups) == 0 {
		return trace.BadParameter("invalid claims received")
	}
	return nil
}

const (
	clusterRoleTemplate = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: teleport-role
rules:
- apiGroups:
  - ""
  resources:
  - users
  - groups
  - serviceaccounts
  verbs:
  - impersonate
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
- apiGroups:
  - "authorization.k8s.io"
  resources:
  - selfsubjectaccessreviews
  - selfsubjectrulesreviews
  verbs:
  - create
`
	clusterRoleBindingTemplate = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: teleport-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: teleport-role
subjects:
- kind: Group
  name: {group_name}
  apiGroup: rbac.authorization.k8s.io`
)
