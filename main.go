package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"time"
	_ "time/tzdata" // Import tzdata to embed time zone data

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/testcon/{eth}/{target}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		eth := vars["eth"]
		target := vars["target"]
		fmt.Printf("eth: %s\n", eth)
		fmt.Printf("target: %s\n", target)
		err := makeHttpCallWithPacketCapture(eth, target)
		if err != nil {
			fmt.Println("Error making http call with packet capture: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			fmt.Fprint(w, "Success")
		}
	})

	fmt.Println("Server is running on port 8080...")
	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func makeHttpCallWithPacketCapture(eth string, target string) error {
	outputFile := getoutputFileName()
	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure the cancel function is called to release resources

	// Run the `tcpdump` command with the context
	cmd := exec.CommandContext(ctx, "tcpdump", "-i", "any", "-s", "0", "-vvv", "-w", outputFile)

	// Capture standard error
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("Error creating stderr pipe: %v", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Error starting tcpdump: %v", err)
	}

	time.Sleep(2 * time.Second)

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
			time.Sleep(2 * time.Second)
			// Cancel the context to stop tcpdump
			cancel() // Cancel the context to stop tcpdump
		}()
		switch target {
		case "internet":
			err = testInternetConnectivity(eth)
		case "private":
			err = getSecretWithDefaultCreds(eth)
		}
		if err != nil {
			fmt.Printf("Error: %v\n", err)
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
				return fmt.Errorf("Output file not created: %v", statErr)
			}
		} else {
			fmt.Println("tcpdump command finished successfully")
		}
	}

	fmt.Printf("tcpdump output written to %s\n", outputFile)
	return nil
}

func getSecretWithDefaultCreds(eth string) error {
	fmt.Println("Getting secrets with default creds")

	cred, err := azidentity.NewWorkloadIdentityCredential(nil)
	if err != nil {
		return fmt.Errorf("Error creating new WorkloadIdentityCredential: %v", err)
	}

	fmt.Printf("Initialize new Client\n")
	// initialize keyvault client
	opts := &azsecrets.ClientOptions{}

	if eth != "def" {
		opts, err = getClientOptionsWithTransport(eth)
		if err != nil {
			return fmt.Errorf("Error getting client options with transport: %v", err)
		}
		fmt.Printf("Getting secrets through %s ip\n", eth)
	} else {
		fmt.Println("Getting secrets through default ip")
	}
	client, err := azsecrets.NewClient("https://isaacskvault.vault.azure.net/", cred, opts)
	if err != nil {
		return fmt.Errorf("Error creating new client: %v", err)
	}

	// Retrieve a secret
	secretName := "test"
	fmt.Printf("Getting secret: %s\n", secretName)
	resp, err := client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		return fmt.Errorf("Error getting secret: %v", err)
	} else {
		fmt.Printf("Secret value: %s\n", *resp.Value)
	}
	return nil
}

func testInternetConnectivity(eth string) error {
	if eth != "def" {
		// Get the eth0 IP address
		eth0IP, err := getethIP(eth)
		if err != nil {
			return fmt.Errorf("Error getting eth0 IP: %v", err)
		}

		fmt.Printf("Testing internet connectivity with %s IP address\n", eth)
		// make a request to www.google.com using eth0 IP address as local address
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					LocalAddr: &net.TCPAddr{
						IP: eth0IP,
					},
				}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
		_, err = client.Get("http://www.google.com")
		if err != nil {
			return fmt.Errorf("No internet connectivity err: %v", err)
		} else {
			fmt.Println("Internet connectivity available")
		}
	} else {
		fmt.Println("Testing internet connectivity without specifying interface")
		_, err := http.Get("http://www.google.com")
		if err != nil {
			return fmt.Errorf("No internet connectivity err: %v", err)
		} else {
			fmt.Println("Internet connectivity available")
		}
	}
	return nil
}
