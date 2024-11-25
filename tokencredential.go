package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// clientAssertionCredential authenticates an application with assertions provided by a callback function.
type clientAssertionCredential struct {
	assertion, file string
	client          confidential.Client
	lastRead        time.Time
}

// newClientAssertionCredential constructs a clientAssertionCredential. Pass nil for options to accept defaults.
func newClientAssertionCredential(tenantID, clientID, authorityHost, file, eth string) (*clientAssertionCredential, error) {
	c := &clientAssertionCredential{file: file}

	cred := confidential.NewCredFromAssertionCallback(
		func(ctx context.Context, _ confidential.AssertionRequestOptions) (string, error) {
			return c.getAssertion(ctx)
		},
	)

	authority, err := url.JoinPath(authorityHost, tenantID)
	fmt.Println(authority)
	if err != nil {
		return nil, fmt.Errorf("failed to construct authority URL: %w", err)
	}

	opts := confidential.WithHTTPClient(&http.Client{})
	if eth == "eth0" {
		fmt.Println("AcquireTokenByCredential through eth0 ip")
		opts = confidential.WithHTTPClient(
			&http.Client{
				Transport: &CustomTransporter{},
				Timeout:   10 * time.Second,
			})
	} else {
		fmt.Println("AcquireTokenByCredential through default ip")
	}

	client, err := confidential.New(authority, clientID, cred, opts)

	if err != nil {
		return nil, fmt.Errorf("failed to create confidential client: %w", err)
	}
	c.client = client

	return c, nil
}

// GetToken implements the TokenCredential interface
func (c *clientAssertionCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// get the token from the confidential client
	fmt.Println("Getting token")
	token, err := c.client.AcquireTokenByCredential(ctx, opts.Scopes)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{
		Token:     token.AccessToken,
		ExpiresOn: token.ExpiresOn,
	}, nil
}

// getAssertion reads the assertion from the file and returns it
// if the file has not been read in the last 5 minutes
func (c *clientAssertionCredential) getAssertion(context.Context) (string, error) {
	fmt.Println("Getting Assertion")
	if now := time.Now(); c.lastRead.Add(5 * time.Minute).Before(now) {
		content, err := os.ReadFile(c.file)
		if err != nil {
			return "", err
		}
		c.assertion = string(content)
		c.lastRead = now
	}
	return c.assertion, nil
}

func getEth0IP() net.IP {
	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Iterate over the interfaces to find eth0
	for _, iface := range interfaces {
		if iface.Name == "eth0" {
			// Get the addresses associated with eth0
			addrs, err := iface.Addrs()
			if err != nil {
				panic(err)
			}

			// Iterate over the addresses to find the IP address
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// return the IP address
				if ip != nil && ip.To4() != nil {
					fmt.Printf("ETH0 IP address: %s\n", ip)
					return ip
				}
			}
		}
	}
	panic("eth0 not found")
}

// CustomTransporter struct that will implement the Transporter interface
type CustomTransporter struct{}

// Implement the RoundTrip method for MyTransporter
func (t *CustomTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Println("RoundTrip")
	// send the request using an HTTP client that uses the local address of eth0
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: getEth0IP(),
				},
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	return client.Do(req)
}

func getSecretWithClientAssertion(eth string) {
	fmt.Println("Getting secrets with client assertion")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	authorityHost := os.Getenv("AZURE_AUTHORITY_HOST")

	if clientID == "" {
		panic("AZURE_CLIENT_ID environment variable is not set")
	} else {
		fmt.Printf("Client ID: %s\n", clientID)
	}
	if tenantID == "" {
		panic("AZURE_TENANT_ID environment variable is not set")
	} else {
		fmt.Printf("Tenant ID: %s\n", tenantID)
	}
	if tokenFilePath == "" {
		panic("AZURE_FEDERATED_TOKEN_FILE environment variable is not set")
	} else {
		fmt.Printf("Token file path: %s\n", tokenFilePath)
	}
	if authorityHost == "" {
		panic("AZURE_AUTHORITY_HOST environment variable is not set")
	} else {
		fmt.Printf("Authority host: %s\n", authorityHost)
	}

	// Initialize a new client assertion credential
	cred, err := newClientAssertionCredential(tenantID, clientID, authorityHost, tokenFilePath, eth)
	if err != nil {
		panic(err)
	}

	// Initialize a new Key Vault client
	opts := &azsecrets.ClientOptions{
		DisableChallengeResourceVerification: true,
	}
	if eth != "" {
		fmt.Println("Getting secrets through %s ip", eth)
		opts, err = getClientOptionsWithTransport(eth)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Getting secrets through default ip")
	}
	client, err := azsecrets.NewClient("https://isaacskvault.vault.azure.net/", cred, opts)
	if err != nil {
		panic(err)
	}

	// Retrieve a secret
	secretName := "test"
	fmt.Printf("Getting secret: %s\n", secretName)
	resp, err := client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Secret value: %s\n", *resp.Value)
	}
}
