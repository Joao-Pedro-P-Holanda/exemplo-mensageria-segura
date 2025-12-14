import { encryptWithServerCert } from "./integrity";
import './styles.css';

let username = '';
let wsSocket = null;

function getWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = '8080';
    return `${protocol}//${host}:${port}/ws`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const content = messageInput.value.trim();

    if (!content || !wsSocket) {
        return;
    }

    const message = JSON.stringify({
        username: username,
        content: content,
        type: 'chat'
    });

    wsSocket.send(message);
    messageInput.value = '';
    messageInput.focus();
}

function displayMessage(message) {
    const messagesContainer = document.getElementById('messages');
    const messageDiv = document.createElement('div');

    if (message.type === 'join' || message.type === 'leave') {
        messageDiv.className = 'message system';
        messageDiv.innerHTML = `<div class="message-content">${escapeHtml(message.content)}</div>`;
    } else {
        const isOwnMessage = message.username === username;
        messageDiv.className = 'message';
        messageDiv.innerHTML = `
            <div class="message-header">
                <strong>${escapeHtml(message.username)}</strong>
                ${isOwnMessage ? ' (You)' : ''}
            </div>
            <div class="message-content">${escapeHtml(message.content)}</div>
        `;
    }

    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
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

    // Set WebSocket URL and connect using htmx
    const chatContainer = document.getElementById('chat-container');
    const wsUrl = getWebSocketUrl();
    chatContainer.setAttribute('ws-connect', wsUrl);

    // Use setTimeout to ensure DOM is ready before processing
    setTimeout(() => {
        // Trigger htmx to process the WebSocket connection
        htmx.process(chatContainer);

        // Focus on message input
        document.getElementById('message-input').focus();
    }, 0);
}

document.addEventListener('DOMContentLoaded', () => {
    const joinBtn = document.getElementById('join-btn');
    const usernameInput = document.getElementById('username-input');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    // Join button click
    joinBtn.addEventListener('click', joinChat);
    // Enter key in username input
    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            joinChat();
        }
    });

    // Send button click
    sendBtn.addEventListener('click', (e) => {
        e.preventDefault();
        sendMessage();
    });

    // Enter key in message input
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // WebSocket opened
    document.body.addEventListener('htmx:wsOpen', (event) => {
        console.log('WebSocket connected');
        statusDot.classList.remove('disconnected');
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';

        // Store WebSocket reference
        wsSocket = event.detail.socketWrapper;

        // Send join message
        const joinMsg = JSON.stringify({
            username: username,
            content: `${username} joined the chat`,
            type: 'join'
        });
        wsSocket.send(joinMsg);
    });

    // WebSocket closed
    document.body.addEventListener('htmx:wsClose', () => {
        console.log('WebSocket disconnected');
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
        wsSocket = null;
    });

    // WebSocket error
    document.body.addEventListener('htmx:wsError', (event) => {
        console.error('WebSocket error:', event);
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    });

    // Handle incoming messages
    document.body.addEventListener('htmx:wsBeforeMessage', (event) => {
        try {
            const message = JSON.parse(event.detail.message);

            if (!message || !message.username || !message.content || !message.type) {
                console.warn('Invalid message format:', message);
                event.preventDefault();
                return;
            }

            displayMessage(message);

            // Prevent htmx from processing as HTML
            event.preventDefault();
        } catch (e) {
            console.error('Error parsing message:', e);
            event.preventDefault();
        }
    });

    // Send leave message on page unload
    window.addEventListener('beforeunload', () => {
        if (username && wsSocket && wsSocket.send) {
            try {
                const leaveMsg = JSON.stringify({
                    username: username,
                    content: `${username} left the chat`,
                    type: 'leave'
                });
                wsSocket.send(leaveMsg);
            } catch (e) {
                console.log('Could not send leave message');
            }
        }
    });
});
