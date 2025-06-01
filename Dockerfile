# Stage 1: Builder
FROM golang:alpine AS builder

ARG BUILD_MODE=release
WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application source code
COPY . .

# Build the Go application
# Statically link and strip symbols for release mode
# Keep symbols for debug mode
RUN     if [ "${BUILD_MODE}" = "release" ]; then         CGO_ENABLED=0 GOOS=linux go build             -a             -ldflags="-s -w"             -o spffy             main.go;     else         CGO_ENABLED=0 GOOS=linux go build             -a             -o spffy             main.go;     fi

# Stage 2: Final image
FROM alpine:latest

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled binary from the builder stage
COPY --from=builder /app/spffy /usr/local/bin/spffy

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/spffy

# Switch to the non-root user
USER appuser

# Expose the port the application listens on (as seen in main.go)
EXPOSE 8053

# Set the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/spffy"]

# Optional: Set default command-line arguments if needed
# CMD ["--basedomain", "example.com"]
