import pem from "./cert.pem"

/**
 * Generates an ephemeral key pair using Web Crypto API
 * @returns {Promise<Object>} Object containing privateKey and publicKey in JWK format
 */
async function generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256" // secp256k1 is not supported in Web Crypto, using P-256
        },
        true, // extractable
        ["deriveKey", "deriveBits"]
    );
}


async function generateEphemeralSecret(privateKey, publicKey) {
    return await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        256
    );
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function importServerPublicKey(jwk) {
    return await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
    );
}

async function deriveSymmetricKey(sharedSecret, saltB64) {
    const salt = base64ToBytes(saltB64);
    const secretBytes = new Uint8Array(sharedSecret);

    const combined = new Uint8Array(salt.length + secretBytes.length);
    combined.set(salt);
    combined.set(secretBytes, salt.length);

    const digest = await crypto.subtle.digest("SHA-256", combined);
    return crypto.subtle.importKey(
        "raw",
        digest,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptWithAesGcm(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
    );

    return {
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
        iv: bytesToBase64(iv)
    };
}

async function decryptWithAesGcm(key, ciphertextB64, ivB64) {
    const ciphertext = base64ToBytes(ciphertextB64);
    const iv = base64ToBytes(ivB64);

    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(plaintext);
}

/**
 * Encrypts data using RSA-OAEP with the server's public key
 * @param {string} data - The data to encrypt
 * @param {string} pemPublicKey - The server's public key in PEM format
 * @returns {Promise<string>} Base64 encoded encrypted data
 */
async function encryptWithServerCert(data) {
    // Remove PEM header/footer and decode base64
    const pemContents = pem
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
    generateKeyPair,
    generateEphemeralSecret,
    importServerPublicKey,
    deriveSymmetricKey,
    encryptWithAesGcm,
    decryptWithAesGcm,
    encryptWithServerCert
};
