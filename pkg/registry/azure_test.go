package registry

import (
	"github.com/go-kit/kit/log"
	"testing"
)

func Test_HostIsAzureContainerRegistry(t *testing.T) {
	for _, v := range []struct {
		host  string
		isACR bool
	}{
		{
			host:  "azurecr.io",
			isACR: false,
		},
		{
			host:  "",
			isACR: false,
		},
		{
			host:  "gcr.io",
			isACR: false,
		},
		{
			host:  "notazurecr.io",
			isACR: false,
		},
		{
			host:  "example.azurecr.io.not",
			isACR: false,
		},
		// Public cloud
		{
			host:  "example.azurecr.io",
			isACR: true,
		},
		// Sovereign clouds
		{
			host:  "example.azurecr.cn",
			isACR: true,
		},
		{
			host:  "example.azurecr.de",
			isACR: true,
		},
		{
			host:  "example.azurecr.us",
			isACR: true,
		},
	} {
		result := hostIsAzureContainerRegistry(v.host)
		if result != v.isACR {
			t.Fatalf("For test %q, expected isACR = %v but got %v", v.host, v.isACR, result)
		}
	}
}

func Test_CredentialExchange(t *testing.T) {
	r, err := getCliCredentials(azureCloudConfig{
		TenantId: "beb0e246-eb11-4bec-b5cf-1740fa5bd053",
	}, "wiretap.azurecr.io", log.NewNopLogger())
	if err != nil {
		t.Error(err)
	}
	t.Logf("%s", r.password)
	t.Errorf("%s", r.password)
	if r.username != "00000000-0000-0000-0000-000000000000" {
		t.Fail()
	}
}
