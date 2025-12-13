let ws = null;
let username = '';
let isConnected = false;

// Get WebSocket URL from environment or use default
const WS_URL = window.location.hostname === 'localhost' 
    ? 'ws://localhost:8080/ws'
    : `ws://${window.location.hostname}:8080/ws`;

function updateStatus(connected) {
    isConnected = connected;
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('status-text');
    
    if (connected) {
        statusDot.classList.remove('disconnected');
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    } else {
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    }
}

function connectWebSocket() {
    try {
        ws = new WebSocket(WS_URL);
        
        ws.onopen = () => {
            console.log('Connected to WebSocket server');
            updateStatus(true);
            
            // Send join message
            const joinMsg = {
                username: username,
                content: `${username} joined the chat`,
                type: 'join'
            };
            ws.send(JSON.stringify(joinMsg));
        };
        
        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                displayMessage(message);
            } catch (e) {
                console.error('Error parsing message:', e);
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateStatus(false);
        };
        
        ws.onclose = () => {
            console.log('Disconnected from WebSocket server');
            updateStatus(false);
            
            // Attempt to reconnect after 3 seconds
            setTimeout(() => {
                if (username) {
                    console.log('Attempting to reconnect...');
                    connectWebSocket();
                }
            }, 3000);
        };
    } catch (error) {
        console.error('Error connecting to WebSocket:', error);
        updateStatus(false);
    }
}

function joinChat() {
    const usernameInput = document.getElementById('username-input');
    username = usernameInput.value.trim();
    
    if (!username) {
        alert('Please enter a username');
        return;
    }
    
    // Hide login section and show chat section
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('chat-section').style.display = 'flex';
    
    // Connect to WebSocket
    connectWebSocket();
    
    // Focus on message input
    document.getElementById('message-input').focus();
}

function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const content = messageInput.value.trim();
    
    if (!content || !isConnected) {
        return;
    }
    
    const message = {
        username: username,
        content: content,
        type: 'chat'
    };
    
    ws.send(JSON.stringify(message));
    messageInput.value = '';
    messageInput.focus();
}

function displayMessage(message) {
    const messagesContainer = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    
    if (message.type === 'join' || message.type === 'leave') {
        messageDiv.className = 'message system';
        messageDiv.innerHTML = `
            <div class="message-content">${escapeHtml(message.content)}</div>
        `;
    } else {
        messageDiv.className = 'message';
        const isOwnMessage = message.username === username;
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <strong>${escapeHtml(message.username)}</strong>
                ${isOwnMessage ? '(You)' : ''}
            </div>
            <div class="message-content">${escapeHtml(message.content)}</div>
        `;
    }
    
    messagesContainer.appendChild(messageDiv);
    
    // Auto-scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event listeners
document.getElementById('username-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        joinChat();
    }
});

document.getElementById('message-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (ws && isConnected) {
        const leaveMsg = {
            username: username,
            content: `${username} left the chat`,
            type: 'leave'
        };
        ws.send(JSON.stringify(leaveMsg));
        ws.close();
    }
});
