import { encryptWithServerCert } from "./integrity";
import './styles.css';

let username = '';

function joinChat() {
    const usernameInput = document.getElementById('username-input');
    username = usernameInput.value.trim();

    if (!username) {
        alert('Please enter a username');
        return;
    }

    // Set the hidden username field for form submission
    document.getElementById('hidden-username').value = username;

    // Hide login section and show chat section
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('chat-section').style.display = 'flex';

    // Use setTimeout to ensure DOM is ready before processing
    setTimeout(() => {
        // Trigger htmx to process the WebSocket connection
        const chatContainer = document.getElementById('chat-container');
        htmx.process(chatContainer);

        // Focus on message input
        document.getElementById('message-input').focus();
    }, 0);
}

document.addEventListener('DOMContentLoaded', () => {
    const joinBtn = document.getElementById('join-btn');
    const usernameInput = document.getElementById('username-input');
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

    // WebSocket open
     document.body.addEventListener('htmx:wsOpen', (event) => {
        console.log('WebSocket connected');
        statusDot.classList.remove('disconnected');
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    })

    // WebSocket closed
    document.body.addEventListener('htmx:wsClose', () => {
        console.log('WebSocket disconnected');
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    });

    // WebSocket error
    document.body.addEventListener('htmx:wsError', (event) => {
        console.error('WebSocket error:', event);
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    });
});
