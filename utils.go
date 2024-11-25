package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

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

func getClientOptionsWithTransport(eth string) (*azsecrets.ClientOptions, error) {
	// Get the eth IP address
	ethIP, err := getethIP(eth)
	if err != nil {
		return nil, fmt.Errorf("Error getting eth IP: %v", err)
	}

	// Create a TCP address with the eth0 IP address
	localAddr := &net.TCPAddr{
		IP: ethIP,
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
		Timeout:   10 * time.Second,
	}

	// Create a ClientOptions with the custom HTTP client
	clientOptions := &azcore.ClientOptions{
		Transport: httpClient,
	}
	opts := &azsecrets.ClientOptions{
		ClientOptions: *clientOptions,
	}
	return opts, nil
}

func getethIP(eth string) (net.IP, error) {
	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Error getting network interfaces: %v", err)
	}

	// Iterate over the interfaces to find eth
	for _, iface := range interfaces {
		if iface.Name == eth {
			// Get the addresses associated with eth
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, error(err)
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
					fmt.Printf("%s IP address: %s\n", eth, ip)
					return ip, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("%s not found", eth)
}
