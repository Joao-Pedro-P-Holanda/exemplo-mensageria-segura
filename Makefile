.PHONY: build-server build run clean

# Build the Go server binary for Linux
build-server:
	cd server && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server-linux main.go

# Build all Docker images
build: build-server
	docker compose build

# Run the entire application
run: build
	docker compose up -d

# Stop and remove containers
stop:
	docker compose down

# View logs
logs:
	docker compose logs -f

# Clean up build artifacts and containers
clean:
	docker compose down -v
	rm -f server/server server/server-linux
