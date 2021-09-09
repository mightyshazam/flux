package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
)

const (
	// Mount volume from hostpath.
	azureCloudConfigJsonFile = "/etc/kubernetes/azure.json"
	azureResource            = "https://management.core.windows.net/"
)

type azureAcrAccessToken struct {
	token string
	refreshToken string
	spt   *adal.ServicePrincipalToken
}

type azureCloudConfig struct {
	AADClientId          string `json:"aadClientId"`
	AADClientSecret      string `json:"aadClientSecret"`
	SubscriptionId       string `json:"subscriptionId"`
	TenantId             string `json:"tenantId"`
	UserAssignedIdentity string `json:"userAssignedIdentityID"`
	Cloud                string `json:"cloud"`
}

func ImageCredsWithAzureAuth(lookup func() ImageCreds, logger log.Logger) (func() error, func() ImageCreds) {
	azureCreds := NoCredentials()

	registryTokens := map[string]azureAcrAccessToken{}
	// we can get an error when refreshing the credentials; to avoid
	// spamming the log, keep track of failed refreshes.
	regionEmbargo := map[string]time.Time{}

	// should this registry be scanned?
	ensureCreds := func(domain string, now time.Time) error {
		// if we had an error getting a token before, don't try again
		// until the embargo has passed
		{
			if embargo, ok := regionEmbargo[domain]; ok {
				if embargo.After(now) {
					return nil // i.e., fail silently
				}
				delete(regionEmbargo, domain)
			}

			// if we don't have the entry at all, we need to get a
			// token. NB we can't check the inverse and return early,
			// since if the creds do exist, we need to check their expiry.
			if c := azureCreds.credsFor(domain, logger); c == (creds{}) {
				goto refresh
			}

			// otherwise, check if the tokens have expired
			expiry, ok := registryTokens[domain];
			if !ok || expiry.spt.Token().IsExpired() {
				logger.Log("info", "need to refresh token", "domain", domain, "expires", expiry)
				goto refresh
			}

			accessToken, err := getAcrTokenFromRefreshToken(
				context.Background(),
				containerregistry.New(domain),
				logger,
				domain,
				expiry.refreshToken)

			if err != nil {
				logger.Log("error", "failed to retrieve access token with refresh token", "err", err)
				return err
			}

			repoCreds := azureAcrAccessToken{
				token:        accessToken,
				refreshToken: expiry.refreshToken,
				spt:          expiry.spt,
			}

			azureCreds.Merge(Credentials{m: map[string]creds{
				domain: credsFromServicePrincipalCreds(domain, repoCreds),
			}})
		}
		// the creds exist and are before the use-by; nothing to be done.
		return nil

	refresh:
		// unconditionally append the sought-after account, and let
		// the AWS API figure out if it's a duplicate.
		logger.Log("info", "attempting to refresh auth tokens", "registry", domain)
		repoCreds, err := fetchServicePrincipalCreds(domain, logger)
		if err != nil {
			regionEmbargo[domain] = now.Add(embargoDuration)
			logger.Log("error", "fetching credentials for registry", "registry", domain, "err", err, "embargo", embargoDuration)
			return err
		}

		registryTokens[domain] = repoCreds
		azureCreds.Merge(Credentials{m: map[string]creds{
			domain: credsFromServicePrincipalCreds(domain, repoCreds),
		}})
		return nil
	}

	lookupACR := func() ImageCreds {
		imageCreds := lookup()

		for name, creds := range imageCreds {
			domain := name.Domain
			if !hostIsAzureContainerRegistry(domain) {
				continue
			}

			/*
				if preflightErr != nil {
					logger.Log("warning", "AWS auth implied by ECR image, but AWS API is not available. You can ignore this if you are providing credentials some other way (e.g., through imagePullSecrets)", "image", name.String(), "err", preflightErr)
				}*/

			if err := ensureCreds(domain, time.Now()); err != nil {
				logger.Log("warning", "unable to ensure credentials for ECR", "domain", domain, "err", err)
			}
			newCreds := NoCredentials()
			newCreds.Merge(azureCreds)
			newCreds.Merge(creds)
			imageCreds[name] = newCreds
		}
		return imageCreds
	}

	return func() error {
		return nil
	}, lookupACR
}

func getAzureCloudConfig() (azureCloudConfig, error) {
	var token azureCloudConfig
	jsonFile, err := ioutil.ReadFile(azureCloudConfigJsonFile)
	if err != nil {
		return token, err
	}

	err = json.Unmarshal(jsonFile, &token)
	if err != nil {
		return token, err
	}

	return token, err
}

func credsFromServicePrincipalCreds(host string, token azureAcrAccessToken) creds {
	return creds{
		username:   "00000000-0000-0000-0000-000000000000",
		password:   token.token,
		registry:   host,
		provenance: "AzureMSI",
	}
}

// Fetch Azure Active Directory clientid/secret pair from azure.json, usable for container registry authentication.
//
// Note: azure.json is populated by AKS/AKS-Engine script kubernetesconfigs.sh. The file is then passed to kubelet via
// --azure-container-registry-config=/etc/kubernetes/azure.json, parsed by kubernetes/kubernetes' azure_credentials.go
// https://github.com/kubernetes/kubernetes/issues/58034 seeks to deprecate this kubelet command-line argument, possibly
// replacing it with managed identity for the Node VMs. See https://github.com/Azure/acr/blob/master/docs/AAD-OAuth.md
func getAzureCloudConfigAADToken(host string, logger log.Logger) (creds, error) {
	token, err := fetchServicePrincipalCreds(host, logger)
	if err != nil {
		return creds{}, err
	}


	return credsFromServicePrincipalCreds(host, token), nil
	/*
		return creds{
			registry:   host,
			provenance: "azure.json",
			username:   token.AADClientId,
			password:   token.AADClientSecret}, nil*/
}

// List from https://github.com/kubernetes/kubernetes/blob/master/pkg/credentialprovider/azure/azure_credentials.go
func hostIsAzureContainerRegistry(host string) bool {
	for _, v := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, v) {
			return true
		}
	}
	return false
}

func getAcrToken(ctx context.Context, cfg azureCloudConfig, registry string, token *adal.ServicePrincipalToken, logger log.Logger) (azureAcrAccessToken, error) {
	cl := containerregistry.New(fmt.Sprintf("https://%s", registry))
	refresh, err := cl.GetAcrRefreshTokenFromExchange(ctx, "access_token", registry, cfg.TenantId, "", token.Token().AccessToken)
	if err != nil {
		logger.Log("error", errors.Wrap(err, "failed to retrieve refresh token"))
		return azureAcrAccessToken{}, err
	}

	access, err := getAcrTokenFromRefreshToken(ctx, cl, logger, registry, *refresh.RefreshToken);
	if err != nil {
		return azureAcrAccessToken{}, nil
	}

	return azureAcrAccessToken{
		token: access,
		refreshToken: *refresh.RefreshToken,
		spt:   token,
	}, nil
	/*
		return creds{
			username:   "00000000-0000-0000-0000-000000000000",
			password:   *refresh.RefreshToken,
			registry:   registry,
			provenance: "AzureMSI",
		}, nil*/
}

func getAcrTokenFromRefreshToken(
	ctx context.Context,
	cl containerregistry.BaseClient,
	logger log.Logger,
	registry string,
	refreshToken string) (string, error) {
	access, err := cl.GetAcrAccessToken(ctx, registry, "registry:catalog:*", refreshToken)
	if err != nil {
		logger.Log("error", errors.Wrap(err, "failed to retrieve access token"))
		return "", err
	}

	return *access.AccessToken, nil
}

func fetchServicePrincipalCreds(registry string, logger log.Logger) (azureAcrAccessToken, error) {
	ctx := context.Background()

	cfg, err := getAzureCloudConfig()
	if err != nil {
		return azureAcrAccessToken{}, err
	}

	azureEnv, err := azure.EnvironmentFromName(cfg.Cloud)
	if err != nil {
		logger.Log("err", err.Error())
		return azureAcrAccessToken{}, err
	}

	var spt *adal.ServicePrincipalToken
	if cfg.AADClientId == "msi" {
		spt, err = getMsiPrincipalToken(azureEnv, cfg, registry, logger)
	} else {
		spt, err = getServicePrincipalToken(azureEnv, cfg, registry, logger)
	}

	err = spt.Refresh()
	if err != nil {
		logger.Log("err", err)
		return azureAcrAccessToken{}, err
	}

	return getAcrToken(ctx, cfg, registry, spt, logger)
}

func getMsiPrincipalToken(env azure.Environment, cfg azureCloudConfig, registry string, logger log.Logger) (*adal.ServicePrincipalToken, error) {
	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		return nil, err
	}

	if cfg.UserAssignedIdentity == "" {
		return adal.NewServicePrincipalTokenFromMSI(msiEndpoint, env.ServiceManagementEndpoint)
	}

	return adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, env.ServiceManagementEndpoint, cfg.UserAssignedIdentity)
}

func getServicePrincipalToken(env azure.Environment, cfg azureCloudConfig, registry string, logger log.Logger) (*adal.ServicePrincipalToken, error) {
	adCfg, err := adal.NewOAuthConfig("", cfg.TenantId)
	if err != nil {
		return nil, err
	}

	return adal.NewServicePrincipalToken(*adCfg, cfg.AADClientId, cfg.AADClientSecret, env.ServiceManagementEndpoint)
}
