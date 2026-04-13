# Use the official Golang image as the base image
FROM golang:1.26.2-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

RUN mkdir -p ./build/plugins

# Build the Go app (CLI)
# Helpful for testing + debugging
RUN go build -o ./build/cli .

# Build the plugin
RUN go build -o ./build/plugins/authorizer ./plugin-gen3
