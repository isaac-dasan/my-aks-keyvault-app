# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
FROM golang:1.22 AS builder

# Create and change to the app directory.
WORKDIR /app

# Copy go.mod and go.sum files.
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed.
RUN go mod download

# Copy the source code.
COPY . .

# Build the Go app.
RUN go build -o myapp

# Use a more recent Ubuntu image to run the Go app.
FROM ubuntu:22.04

# Install necessary libraries (if any)
RUN apt-get update && apt-get install -y ca-certificates 
# Update the package list and install necessary tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    iproute2 \
    net-tools \
    iputils-ping \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage.
COPY --from=builder /app/myapp /myapp

# Run the Go app.
ENTRYPOINT ["/myapp"]