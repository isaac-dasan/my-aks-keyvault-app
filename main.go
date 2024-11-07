package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
	_ "time/tzdata" // Import tzdata to embed time zone data

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/getsecret/{eth}/{credType}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		eth := vars["eth"]
		credType := vars["credType"]
		fmt.Printf("eth: %s\n", eth)
		fmt.Printf("credType: %s\n", credType)
		getSecretWithPackets(eth, credType)
	})

	fmt.Println("Server is running on port 8080...")
	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func getoutputFileName() string {
	// Get the current time
	now := time.Now()

	// Load the PST location
	pst, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return "capture.pcap"
	}

	// Convert the current time to PST
	pstTime := now.In(pst)

	// Define the output file with timestamp
	outputFile := fmt.Sprintf("tcpdump-%s.pcap", pstTime.Format("2006-01-02T15-04-05"))
	fmt.Printf("Output file: %s\n", outputFile)
	return outputFile
}

func getSecretWithPackets(eth string, credType string) {
	outputFile := getoutputFileName()
	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure the cancel function is called to release resources

	// Run the `tcpdump` command with the context
	cmd := exec.CommandContext(ctx, "tcpdump", "-i", "any", "-s", "0", "-vvv", "-w", outputFile)

	// Capture standard error
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("Error creating stderr pipe: %v\n", err)
		return
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting tcpdump: %v\n", err)
		return
	}

	time.Sleep(10 * time.Second)

	// Read standard error in a separate goroutine
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				fmt.Printf("tcpdump stderr: %s\n", string(buf[:n]))
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for the command to finish in a separate goroutine
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Simulate some application logic
	go func() {
		defer func() {
			time.Sleep(10 * time.Second)
			// Cancel the context to stop tcpdump
			cancel() // Cancel the context to stop tcpdump
		}()
		if credType == "clientAssertion" {
			getSecretWithClientAssertion(eth)
		} else {
			getSecretWithDefaultCreds(eth)
		}
	}()

	// Wait for the command to finish or an error to occur
	select {
	case <-ctx.Done():
		fmt.Println("tcpdump command was cancelled")
	case err := <-done:
		if err != nil {
			fmt.Printf("tcpdump command finished with error: %v\n", err)
			// Check if the output file was created
			if _, statErr := exec.Command("ls", outputFile).Output(); statErr != nil {
				fmt.Printf("Output file not created: %v\n", statErr)
			}
		} else {
			fmt.Println("tcpdump command finished successfully")
		}
	}

	fmt.Printf("tcpdump output written to %s\n", outputFile)
}

func getSecretWithDefaultCreds(eth string) {
	fmt.Println("Getting secrets with default creds")

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Initialize new Client\n")
	// initialize keyvault client
	opts := &azsecrets.ClientOptions{}

	if eth == "eth0" {
		opts = getClientOptionsWithTransport()
		fmt.Println("Getting secrets through eth0 ip")
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

func getSecretWithClientAssertion(eth string) {
	fmt.Println("Getting secrets with client assertion")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	authorityHost := os.Getenv("AZURE_AUTHORITY_HOST")

	if clientID == "" {
		panic("AZURE_CLIENT_ID environment variable is not set")
	}
	if tenantID == "" {
		panic("AZURE_TENANT_ID environment variable is not set")
	}
	if tokenFilePath == "" {
		panic("AZURE_FEDERATED_TOKEN_FILE environment variable is not set")
	}
	if authorityHost == "" {
		panic("AZURE_AUTHORITY_HOST environment variable is not set")
	}
	// Initialize a new client assertion credential
	cred, err := newClientAssertionCredential(tenantID, clientID, authorityHost, tokenFilePath, eth)
	if err != nil {
		panic(err)
	}

	// Initialize a new Key Vault client
	opts := &azsecrets.ClientOptions{}
	if eth == "eth0" {
		fmt.Println("Getting secrets through eth0 ip")
		opts = getClientOptionsWithTransport()
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

func getClientOptionsWithTransport() *azsecrets.ClientOptions {
	// Get the eth0 IP address
	eth0IP := getEth0IP()
	// Create a TCP address with the eth0 IP address
	localAddr := &net.TCPAddr{
		IP: eth0IP,
	}

	// Create a custom http.Transport with LocalAddr set
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			LocalAddr: localAddr,
			Timeout:   10 * time.Second,
		}).DialContext,
	}

	// Create an HTTP client with the custom transport
	httpClient := &http.Client{
		Transport: transport,
	}

	// Create a ClientOptions with the custom HTTP client
	clientOptions := &azcore.ClientOptions{
		Transport: httpClient,
	}
	opts := &azsecrets.ClientOptions{
		ClientOptions: *clientOptions,
	}
	return opts
}
