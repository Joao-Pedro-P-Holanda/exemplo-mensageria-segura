import pem from "./cert.pem"

/**
 * Generates an ephemeral key pair using Web Crypto API
 * @returns {Promise<Object>} Object containing privateKey and publicKey in JWK format
 */
async function generateKeyPair() {
	return await window.crypto.subtle.generateKey(
		{
			name: "ECDH",
			namedCurve: "P-256", // secp256k1 is not supported in Web Crypto, using P-256
		},
		true, // extractable
		["deriveKey", "deriveBits"],
	)
}

async function generateEphemeralSecret(privateKey, publicKey) {
	return await crypto.subtle.deriveBits(
		{
			name: "ECDH",
			public: publicKey,
		},
		privateKey,
		256,
	)
}

function base64UrlToBase64(str) {
	let base64 = str.replace(/-/g, "+").replace(/_/g, "/")
	while (base64.length % 4 !== 0) {
		base64 += "="
	}
	return base64
}

function base64ToBytes(b64url) {
	const b64 = base64UrlToBase64(b64url)
	const binary = atob(b64)
	const bytes = new Uint8Array(binary.length)
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i)
	}
	return bytes
}

function bytesToBase64(bytes) {
	let binary = ""
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i])
	}
	return btoa(binary)
}

async function importServerPublicKey(jwk) {
	return await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, [])
}

async function deriveSymmetricKey(sharedSecret, saltB64) {
	const salt = base64ToBytes(saltB64)
	const secretBytes = new Uint8Array(sharedSecret)

	const combined = new Uint8Array(salt.length + secretBytes.length)
	combined.set(salt)
	combined.set(secretBytes, salt.length)

	const digest = await crypto.subtle.digest("SHA-256", combined)
	return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"])
}

async function encryptWithAesGcm(key, plaintext) {
	const iv = crypto.getRandomValues(new Uint8Array(12))
	const encoded = new TextEncoder().encode(plaintext)

	const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)

	return {
		ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
		iv: bytesToBase64(iv),
	}
}

async function decryptWithAesGcm(key, ciphertextB64, ivB64) {
	const ciphertext = base64ToBytes(ciphertextB64)
	const iv = base64ToBytes(ivB64)

	const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)

	return new TextDecoder().decode(plaintext)
}

/**
 * Encrypts data using RSA-OAEP with the server's public key
 * @param {string} data - The data to encrypt
 * @param {string} pemPublicKey - The server's public key in PEM format
 * @returns {Promise<string>} Base64 encoded encrypted data
 */
async function encryptWithServerCert(data) {
	const pemHeader = "-----BEGIN PUBLIC KEY-----"
	const pemFooter = "-----END PUBLIC KEY-----"
	const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length - 1)
	// base64 decode the string to get the binary data
	const binaryDerString = window.atob(pemContents)
	// convert from a binary string to an ArrayBuffer
	const binaryDer = str2ab(binaryDerString)

	const publicKey = await window.crypto.subtle.importKey(
		"spki",
		binaryDer,
		{
			name: "RSA-OAEP",
			hash: "SHA-256",
		},
		true,
		["encrypt"],
	)

	const encoder = new TextEncoder()
	const dataBuffer = encoder.encode(data)

	const encrypted = await window.crypto.subtle.encrypt(
		{
			name: "RSA-OAEP",
		},
		publicKey,
		dataBuffer,
	)

	return window.btoa(ab2str(encrypted))
}

// TODO: Check if the signature corresponds to the content with AEAD
async function verifyServerSignature(signature, payloadBytes) {
	const pemHeader = "-----BEGIN PUBLIC KEY-----"
	const pemFooter = "-----END PUBLIC KEY-----"

	const pemContents = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "")

	const binaryDer = str2ab(atob(pemContents))

	const publicKey = await crypto.subtle.importKey("spki", binaryDer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"])

	let signatureBytes

	if (typeof signature === "string") {
		signatureBytes = base64ToBytes(signature)
	} else if (signature instanceof Uint8Array) {
		signatureBytes = signature
	} else if (signature instanceof ArrayBuffer) {
		signatureBytes = new Uint8Array(signature)
	} else {
		throw new Error("Formato de assinatura inválido")
	}

	return crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signatureBytes, payloadBytes)
}

function str2ab(str) {
	const buf = new ArrayBuffer(str.length)
	const bufView = new Uint8Array(buf)
	for (let i = 0, strLen = str.length; i < strLen; i++) {
		bufView[i] = str.charCodeAt(i)
	}
	return buf
}

function ab2str(buf) {
	return String.fromCharCode.apply(null, new Uint8Array(buf))
}

export {
	generateKeyPair,
	generateEphemeralSecret,
	importServerPublicKey,
	deriveSymmetricKey,
	encryptWithAesGcm,
	decryptWithAesGcm,
	encryptWithServerCert,
	verifyServerSignature,
}
