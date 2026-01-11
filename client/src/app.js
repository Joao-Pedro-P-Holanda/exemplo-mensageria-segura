import {
    generateKeyPair,
    generateEphemeralSecret,
    importServerPublicKey,
    deriveSymmetricKey,
    encryptWithAesGcm,
    decryptWithAesGcm,
    encryptWithServerCert,
    verifyServerSignature
} from "./integrity";
import {
    generateNonce
} from "./utils"
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
let clientId = process.env.WEBPACK_CLIENT_ID

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
            body: JSON.stringify({ content: await encryptWithServerCert(JSON.stringify(publicJwk)) })
        });

        if (!response.ok) {
            throw new Error('Failed to perform key exchange');
        }

        const data = await response.json();

        if (!verifyServerSignature(data["signature"])) {
            throw new Error("Signature don't match content");
        }

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
    const chatContainer = document.getElementById('chat-container');

    // Join button click
    joinBtn.addEventListener('click', joinChat);

    // Enter key in username input
    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            joinChat();
        }
    });

    // WebSocket open
    document.body.addEventListener('htmx:wsOpen', async () => {
        await ensureHandshake()
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
    chatContainer.addEventListener('htmx:wsConfigSend', async (event) => {
        try {
            event.preventDefault();

            htmx.trigger("#message-form", "htmx:abort")

            if (!symmetricKey) {
                throw new Error('Symmetric key unavailable');
            }
            const payload = JSON.stringify({
                username: username,
                nonce: generateNonce(12),
                content: document.getElementById("message-input").value,
            });

            const { ciphertext, iv } = await encryptWithAesGcm(symmetricKey, payload);
            event.detail.socketWrapper.sendImmediately(JSON.stringify({
                sessionId,
                content: ciphertext,
                iv,
            }));

        } catch (err) {
            console.error('Failed to encrypt outgoing message', err);
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

            // Server sends { content, iv } as the encrypted frame
            if (!incoming || !incoming.content || !incoming.iv) {
                return;
            }

            const plaintext = await decryptWithAesGcm(symmetricKey, incoming.content, incoming.iv);
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
