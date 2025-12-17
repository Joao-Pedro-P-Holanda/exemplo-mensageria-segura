let recipientPublicKey = null;
let myEphemeralKeyPair = null;

async function generateKeyPair() {
    // ...existing code...
}

async function deriveSharedSecret(privateKey, publicKey) {
    // ...existing code...
}

async function encryptMessage(message, sharedSecret) {
    // ...existing code...
}

async function decryptMessage(encryptedMessage, sharedSecret) {
    // ...existing code...
}

async function exchangeEphemeralKey() {
    myEphemeralKeyPair = await generateKeyPair();
    
    const response = await fetch('/exchange-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            publicKey: await exportKey(myEphemeralKeyPair.publicKey)
        })
    });
    
    const data = await response.json();
    recipientPublicKey = await importKey(data.publicKey);
    return true;
}

// Handle message sending - exchange key before sending
document.body.addEventListener('htmx:wsBeforeSend', async (event) => {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value.trim();
    
    if (!message) {
        event.preventDefault();
        return;
    }
    
    // Exchange ephemeral key if needed
    if (!myEphemeralKeyPair || !recipientPublicKey) {
        await exchangeEphemeralKey();
    }
    
    // Encrypt the message
    const sharedSecret = await deriveSharedSecret(myEphemeralKeyPair.privateKey, recipientPublicKey);
    const encryptedMessage = await encryptMessage(message, sharedSecret);
    
    // Modify the request to send encrypted data
    event.detail.parameters = { message: encryptedMessage };
    
    messageInput.value = '';
});

// Handle incoming messages - decrypt after receiving
document.body.addEventListener('htmx:wsAfterMessage', async (event) => {
    const data = JSON.parse(event.detail.message);
    
    if (data.type === 'message' && data.encrypted) {
        // Exchange key if we don't have one
        if (!myEphemeralKeyPair || !recipientPublicKey) {
            await exchangeEphemeralKey();
        }
        
        const sharedSecret = await deriveSharedSecret(myEphemeralKeyPair.privateKey, recipientPublicKey);
        const decryptedMessage = await decryptMessage(data.message, sharedSecret);
        
        // Update the DOM with decrypted message
        const chatContent = document.getElementById('chat-content');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        messageDiv.textContent = `${data.sender}: ${decryptedMessage}`;
        chatContent.appendChild(messageDiv);
        chatContent.scrollTop = chatContent.scrollHeight;
    }
});

async function exportKey(key) {
    // ...existing code...
}

async function importKey(keyData) {
    // ...existing code...
}