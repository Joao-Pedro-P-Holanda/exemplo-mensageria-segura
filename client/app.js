let username = '';
let ws = null;

function updateStatus(connected) {
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

function getWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = window.location.hostname === 'localhost' ? '8080' : '8080';
    return `${protocol}//${host}:${port}/ws`;
}

function joinChat() {
    const usernameInput = document.getElementById('username-input');
    username = usernameInput.value.trim();
    
    if (!username) {
        alert('Please enter a username');
        return;
    }
    
    // Set hidden username field for form submissions
    document.getElementById('hidden-username').value = username;
    
    // Hide login section and show chat section
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('chat-section').style.display = 'flex';
    
    // Set WebSocket URL and connect using htmx
    const messagesContainer = document.getElementById('messages');
    const wsUrl = getWebSocketUrl();
    messagesContainer.setAttribute('ws-connect', wsUrl);
    
    // Trigger htmx to process the WebSocket connection
    htmx.process(messagesContainer);
    
    // Focus on message input
    document.getElementById('message-input').focus();
}

function sendWebSocketMessage(message) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
    }
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
document.addEventListener('DOMContentLoaded', () => {
    const joinBtn = document.getElementById('join-btn');
    joinBtn.addEventListener('click', joinChat);
    
    document.getElementById('username-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            joinChat();
        }
    });
    
    // Listen for htmx WebSocket events
    document.body.addEventListener('htmx:wsOpen', (event) => {
        console.log('WebSocket connected via htmx');
        ws = event.detail.socketWrapper;
        updateStatus(true);
        
        // Send join message
        const joinMsg = {
            username: username,
            content: `${username} joined the chat`,
            type: 'join'
        };
        sendWebSocketMessage(joinMsg);
    });
    
    document.body.addEventListener('htmx:wsClose', () => {
        console.log('WebSocket disconnected via htmx');
        ws = null;
        updateStatus(false);
    });
    
    document.body.addEventListener('htmx:wsError', (event) => {
        console.error('WebSocket error via htmx:', event);
        updateStatus(false);
    });
    
    // Listen for incoming WebSocket messages
    document.body.addEventListener('htmx:wsBeforeMessage', (event) => {
        try {
            const message = JSON.parse(event.detail.message);
            displayMessage(message);
            // Prevent htmx from processing the message as HTML
            event.preventDefault();
        } catch (e) {
            console.error('Error parsing message:', e);
        }
    });
    
    // Handle form submission
    const messageForm = document.getElementById('message-form');
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const messageInput = document.getElementById('message-input');
        const content = messageInput.value.trim();
        
        if (!content) {
            return;
        }
        
        const message = {
            username: username,
            content: content,
            type: 'chat'
        };
        
        sendWebSocketMessage(message);
        
        messageInput.value = '';
        messageInput.focus();
    });
    
    // Handle Enter key in message input
    document.getElementById('message-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            messageForm.dispatchEvent(new Event('submit'));
        }
    });
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (username && ws) {
        const leaveMsg = {
            username: username,
            content: `${username} left the chat`,
            type: 'leave'
        };
        sendWebSocketMessage(leaveMsg);
    }
});
