package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func main() {

	http.HandleFunc("/getsecret", func(w http.ResponseWriter, r *http.Request) {
		getSecretWithPackets()
	})

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func changedefaultroute() {
	// remove existing default route and add new default route
	cmd := exec.Command("ip", "route", "del", "default", "via", "169.254.2.1")
	_, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error running ip route: %v\n", err)
		return
	}

	cmd = exec.Command("ip", "route", "add", "default", "via", "169.254.1.1", "dev", "eth0")
	_, err = cmd.Output()
	if err != nil {
		fmt.Printf("Error running ip route: %v\n", err)
		return
	}
}

func printiproute() {
	// Run the `ip route` command
	cmd := exec.Command("ip", "route")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error running ip route: %v\n", err)
		return
	}
	// Print the output
	fmt.Printf("ip route output:\n%s\n", output)
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

func getSecretWithPackets() {
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
		getSecret()
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

func getSecret() {

	fmt.Printf("Getting creds\n")
	// cred, err := newClientAssertionCredential(tenantID, clientID, authorityHost, tokenFilePath, nil)
	// if err != nil {
	// 	panic(err)
	// }

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Initialize new Client\n")
	// initialize keyvault client
	client, err := azsecrets.NewClient("https://isaacskvault.vault.azure.net/", cred, &azsecrets.ClientOptions{})
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
