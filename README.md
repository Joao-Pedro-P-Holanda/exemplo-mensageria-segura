# exemplo-mensageria-segura
Exemplo de mensageria entre clientes de forma segura

## 📋 Description

This is a monorepo project featuring a real-time chat application with WebSocket support. The project consists of:
- **Server**: A Go-based WebSocket server that manages chat connections and message broadcasting
- **Client**: A modern web-based chat interface served via Nginx

## 🏗️ Architecture

The project is structured as a monorepo with two main components:

```
exemplo-mensageria-segura/
├── server/          # Go WebSocket server
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   └── Dockerfile
├── client/          # Frontend web application
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   ├── nginx.conf
│   └── Dockerfile
└── docker-compose.yml
```

## 🚀 Getting Started

### Prerequisites

- Docker
- Docker Compose
- Go 1.21 or later (for building the server binary)
- Make (optional, for easier build process)

### Running the Application

1. Clone the repository:
```bash
git clone https://github.com/Joao-Pedro-P-Holanda/exemplo-mensageria-segura.git
cd exemplo-mensageria-segura
```

2. Build and start all services:

**Using Make (recommended):**
```bash
make run
```

**Or manually:**
```bash
# Build the server binary
cd server && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server-linux main.go && cd ..

# Start all services
docker compose up --build -d
```

This will start:
- 1 WebSocket server on port `8080`
- 3 client instances accessible at:
  - Client 1: http://localhost:3001
  - Client 2: http://localhost:3002
  - Client 3: http://localhost:3003

3. View logs:
```bash
make logs
# or
docker compose logs -f
```

4. Stop all services:
```bash
make stop
# or
docker compose down
```

### Testing Chat Privacy

To test the chat application with multiple clients:

1. Open three different browser windows/tabs
2. Navigate to each client URL:
   - http://localhost:3001
   - http://localhost:3002
   - http://localhost:3003
3. Enter a different username in each client
4. Start chatting! Messages sent from any client will be broadcast to all connected clients

## 🛠️ Development

### Server Development

The server is built with Go and uses the Gorilla WebSocket library:

```bash
cd server
go run main.go
```

### Client Development

The client is a static HTML/CSS/JavaScript application. You can serve it with any web server:

```bash
cd client
python3 -m http.server 8000
```

## 🔧 Configuration

### Server
- Default port: `8080`
- WebSocket endpoint: `/ws`
- Health check endpoint: `/health`

### Client
- The client automatically connects to the WebSocket server
- Connection URL is determined based on the hostname

## 🐳 Docker

### Building Individual Images

Server:
```bash
docker build -t chat-server ./server
```

Client:
```bash
docker build -t chat-client ./client
```

### Running with Docker Compose

Start services:
```bash
docker-compose up -d
```

Stop services:
```bash
docker-compose down
```

View logs:
```bash
docker-compose logs -f
```

## 📝 Features

- ✅ Real-time WebSocket communication
- ✅ Multiple client support
- ✅ User join/leave notifications
- ✅ Message broadcasting to all connected clients
- ✅ Automatic reconnection on connection loss
- ✅ Modern, responsive UI
- ✅ Docker containerization
- ✅ Health check endpoints

## 🔒 Security Considerations

This is a demonstration project. For production use, consider:
- Implementing authentication and authorization
- Adding message encryption
- Rate limiting
- Input validation and sanitization
- HTTPS/WSS (secure WebSocket)
- CORS configuration
- Session management

## 📄 License

This project is open source and available for educational purposes.
