/**
 * Generates an ephemeral key pair using Web Crypto API
 * @returns {Promise<Object>} Object containing privateKey and publicKey in JWK format
 */
async function generateEphemeralKey() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256" // secp256k1 is not supported in Web Crypto, using P-256
        },
        true, // extractable
        ["sign", "verify"]
    );

    // Export keys to JWK format
    const privateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const publicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

    return {
        privateKey,
        publicKey,
        createdAt: new Date().toISOString()
    };
}

/**
 * Encrypts data using RSA-OAEP with the server's public key
 * @param {string} data - The data to encrypt
 * @param {string} pemPublicKey - The server's public key in PEM format
 * @returns {Promise<string>} Base64 encoded encrypted data
 */
async function encryptWithServerCert(data, pemPublicKey) {
    // Remove PEM header/footer and decode base64
    const pemContents = pemPublicKey
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');

    const binaryDer = atob(pemContents);
    const binaryArray = new Uint8Array(binaryDer.length);
    for (let i = 0; i < binaryDer.length; i++) {
        binaryArray[i] = binaryDer.charCodeAt(i);
    }

    // Import the public key
    const publicKey = await window.crypto.subtle.importKey(
        "spki",
        binaryArray.buffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,
        ["encrypt"]
    );

    // Encrypt the data
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        dataBuffer
    );

    // Convert to base64
    const encryptedArray = new Uint8Array(encrypted);
    let binaryString = '';
    for (let i = 0; i < encryptedArray.length; i++) {
        binaryString += String.fromCharCode(encryptedArray[i]);
    }
    return btoa(binaryString);
}

export {
    generateEphemeralKey,
    encryptWithServerCert
};
