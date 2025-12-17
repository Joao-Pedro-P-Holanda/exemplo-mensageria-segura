import {
    generateKeyPair,
    generateEphemeralSecret,
    importServerPublicKey,
    deriveSymmetricKey,
    encryptWithAesGcm,
    decryptWithAesGcm
} from "./integrity";
import './styles.css';

let username = '';
let symmetricKey = null;
let sessionId = '';
let clientKeys = null;
let handshakePromise = null;

function escapeHTML(value) {
    const div = document.createElement('div');
    div.textContent = value;
    return div.innerHTML;
}

function appendMessage({ username: sender, content }) {
    const container = document.getElementById('messages');
    const wrapper = document.createElement('div');
    wrapper.className = 'message';
    wrapper.innerHTML = `
        <div class="message-header">
            <strong>${escapeHTML(sender || 'Unknown')}</strong>
        </div>
        <div class="message-content">${escapeHTML(content || '')}</div>
    `;
    container.appendChild(wrapper);
}

async function ensureHandshake() {
    if (symmetricKey) return;
    if (handshakePromise) {
        return handshakePromise;
    }

    handshakePromise = (async () => {
        clientKeys = await generateKeyPair();
        const publicJwk = await crypto.subtle.exportKey("jwk", clientKeys.publicKey);

        const response = await fetch('http://localhost:8080/key-exchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ publicKey: publicJwk })
        });

        if (!response.ok) {
            throw new Error('Failed to perform key exchange');
        }

        const data = await response.json();
        sessionId = data.sessionId;

        const serverPublicKey = await importServerPublicKey(data.serverPublicKey);
        const sharedSecret = await generateEphemeralSecret(clientKeys.privateKey, serverPublicKey);
        // Derive symmetric key using salt provided by server
        symmetricKey = await deriveSymmetricKey(sharedSecret, data.salt);
    })();

    await handshakePromise;
}

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
    document.body.addEventListener('htmx:wsOpen', () => {
        console.log('WebSocket connected');
        statusDot.classList.remove('disconnected');
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    });

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

    // Encrypt messages right before htmx sends them over the socket
    document.body.addEventListener('htmx:wsConfigSend', async (event) => {
        try {
            await ensureHandshake();
            if (!symmetricKey) {
                throw new Error('Symmetric key unavailable');
            }

            const outgoing = event.detail.message || {};
            const payload = JSON.stringify({
                username: outgoing.username || username,
                content: outgoing.content || '',
                type: outgoing.type || 'chat'
            });

            const { ciphertext, iv } = await encryptWithAesGcm(symmetricKey, payload);
            event.detail.message = {
                sessionId,
                payload: ciphertext,
                iv,
                type: 'encrypted-chat'
            };
            htmx.logAll();
        } catch (err) {
            console.error('Failed to encrypt outgoing message', err);
            event.preventDefault();
        }
    });

    // Decrypt incoming messages after htmx receives them
    document.body.addEventListener('htmx:wsAfterMessage', async (event) => {
        try {
            if (!symmetricKey) {
                return;
            }

            let incoming = event.detail.message;
            if (typeof incoming === 'string') {
                incoming = JSON.parse(incoming);
            }

            if (!incoming || !incoming.payload || !incoming.iv) {
                return;
            }

            const plaintext = await decryptWithAesGcm(symmetricKey, incoming.payload, incoming.iv);
            const parsed = JSON.parse(plaintext);
            appendMessage(parsed);

            if (event.detail) {
                event.detail.shouldSwap = false;
            }
        } catch (err) {
            console.error('Failed to decrypt incoming message', err);
        }
    });
});
