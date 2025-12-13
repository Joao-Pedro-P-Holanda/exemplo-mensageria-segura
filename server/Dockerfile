# Use a minimal base image
FROM busybox:latest

# Copy the pre-built binary
# Build the binary first with: make build-server
COPY server-linux /server

EXPOSE 8080

CMD ["/server"]
