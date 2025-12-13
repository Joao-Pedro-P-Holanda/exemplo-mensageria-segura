let username = '';

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
    const port = '8080';
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
    const chatContainer = document.getElementById('chat-container');
    const wsUrl = getWebSocketUrl();
    chatContainer.setAttribute('ws-connect', wsUrl);
    
    // Trigger htmx to process the WebSocket connection
    htmx.process(chatContainer);
    
    // Focus on message input
    document.getElementById('message-input').focus();
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
        updateStatus(true);
        
        // Send join message using htmx's WebSocket send
        const chatContainer = document.getElementById('chat-container');
        const joinMsg = JSON.stringify({
            username: username,
            content: `${username} joined the chat`,
            type: 'join'
        });
        
        // Use htmx's WebSocket send mechanism
        htmx.trigger(chatContainer, 'htmx:wsConfigSend', {detail: {message: joinMsg}});
    });
    
    document.body.addEventListener('htmx:wsClose', () => {
        console.log('WebSocket disconnected via htmx');
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
    
    // Intercept form submission to handle with htmx WebSocket
    const messageForm = document.getElementById('message-form');
    messageForm.addEventListener('htmx:wsBeforeSend', (event) => {
        // Clear the input after htmx sends the message
        const messageInput = document.getElementById('message-input');
        setTimeout(() => {
            messageInput.value = '';
            messageInput.focus();
        }, 0);
    });
    
    // Handle Enter key in message input to submit form
    document.getElementById('message-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            messageForm.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
        }
    });
});

// Handle page unload - send leave message
window.addEventListener('beforeunload', () => {
    if (username) {
        const chatContainer = document.getElementById('chat-container');
        const leaveMsg = JSON.stringify({
            username: username,
            content: `${username} left the chat`,
            type: 'leave'
        });
        
        // Try to send leave message
        try {
            htmx.trigger(chatContainer, 'htmx:wsConfigSend', {detail: {message: leaveMsg}});
        } catch (e) {
            console.log('Could not send leave message');
        }
    }
});
