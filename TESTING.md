# Testing Guide

This guide explains how to test the chat application and verify that chat privacy is working correctly.

## Prerequisites

Make sure you have the application running:

```bash
make run
# or
make build-server && docker compose up -d
```

Verify all services are running:
```bash
docker compose ps
```

You should see:
- 1 server (chat-server) on port 8080
- 3 clients (chat-client-1, chat-client-2, chat-client-3) on ports 3001, 3002, 3003

## Testing with Web Browser

### 1. Open Multiple Browser Windows

Open three separate browser windows or tabs:
- Window 1: http://localhost:3001
- Window 2: http://localhost:3002
- Window 3: http://localhost:3003

### 2. Join the Chat

In each window:
1. Enter a unique username (e.g., "Alice", "Bob", "Charlie")
2. Click "Join Chat"

You should see:
- Connection status changes to "Connected" (green dot)
- Join notifications appear in all windows

### 3. Test Message Broadcasting

1. Send a message from Window 1 (Alice)
2. Verify that the message appears in all three windows
3. Send a message from Window 2 (Bob)
4. Verify that the message appears in all three windows
5. Send a message from Window 3 (Charlie)
6. Verify that the message appears in all three windows

### 4. Test Multiple Conversations

You can simulate different chat scenarios:

**Scenario 1: All users in the same room**
- All three clients see all messages
- This demonstrates the broadcast functionality

**Scenario 2: User leaves and rejoins**
1. Close one browser window
2. Other windows should show the user disconnect message
3. Reopen the window and rejoin
4. All windows show the user joined again

## Testing with Command Line (WebSocket Client)

If you have Node.js installed, you can test programmatically:

1. Create a test script:
```javascript
// test-chat.js
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:8080/ws');

ws.on('open', () => {
    console.log('Connected!');
    
    // Send join message
    ws.send(JSON.stringify({
        username: 'TestUser',
        content: 'TestUser joined the chat',
        type: 'join'
    }));
    
    // Send a chat message
    setTimeout(() => {
        ws.send(JSON.stringify({
            username: 'TestUser',
            content: 'Hello from command line!',
            type: 'chat'
        }));
    }, 1000);
});

ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    console.log(`[${msg.type}] ${msg.username}: ${msg.content}`);
});
```

2. Install ws package:
```bash
npm install ws
```

3. Run the test:
```bash
node test-chat.js
```

## Verifying Chat Privacy

To verify that messages are properly isolated and broadcast:

1. **Broadcast Test**: Send a message from any client and verify it appears on all other connected clients
2. **Privacy Test**: Note that in this basic implementation, all messages are broadcast to all clients (no privacy/encryption)
3. **Connection Test**: Connect and disconnect clients to verify proper connection management

## Viewing Server Logs

To see what's happening on the server:

```bash
docker compose logs -f server
```

You should see:
- Client connection/disconnection events
- Total number of connected clients

## Stopping the Application

When you're done testing:

```bash
make stop
# or
docker compose down
```

## Known Limitations

1. **No Message History**: New clients don't see previous messages
2. **No Authentication**: Anyone can join with any username
3. **No Encryption**: Messages are sent in plain text over WebSocket
4. **No Private Rooms**: All users are in the same global chat room
5. **CORS Open**: The server accepts connections from any origin (development mode)

## Next Steps for Production

To make this production-ready, consider adding:
- User authentication and authorization
- End-to-end encryption for messages
- Private chat rooms/channels
- Message persistence and history
- Rate limiting and abuse prevention
- WSS (WebSocket Secure) with TLS/SSL
- Proper CORS configuration
- Input validation and sanitization
