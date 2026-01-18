import {
	generateKeyPair,
	generateEphemeralSecret,
	importServerPublicKey,
	deriveSymmetricKey,
	encryptWithAesGcm,
	decryptWithAesGcm,
	encryptWithServerCert,
	verifyServerSignature,
} from "./integrity"
import { generateNonce } from "./utils"
import "./styles.css"

let username = ""
let symmetricKey = null
let sessionId = ""
let clientKeys = null
let handshakePromise = null

function escapeHTML(value) {
	const div = document.createElement("div")
	div.textContent = value
	return div.innerHTML
}

function appendMessage({ username: sender, content }) {
	const container = document.getElementById("messages")
	const wrapper = document.createElement("div")
	wrapper.className = "message"
	wrapper.innerHTML = `
        <div class="message-header">
            <strong>${escapeHTML(sender || "Unknown")}</strong>
        </div>
        <div class="message-content">${escapeHTML(content || "")}</div>
    `
	container.appendChild(wrapper)
}

async function ensureHandshake() {
	if (symmetricKey) return
	if (handshakePromise) {
		return handshakePromise
	}

	handshakePromise = (async () => {
		clientKeys = await generateKeyPair()
		const publicJwk = await crypto.subtle.exportKey("jwk", clientKeys.publicKey)

		const response = await fetch("http://localhost:8080/key-exchange", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ content: await encryptWithServerCert(JSON.stringify(publicJwk)) }),
		})

		if (!response.ok) {
			throw new Error("Failed to perform key exchange")
		}

		const data = await response.json()

		// base64 -> bytes
		const payloadBytes = Uint8Array.from(atob(data.payload), (c) => c.charCodeAt(0))

		const signatureBytes = Uint8Array.from(atob(data.signature), (c) => c.charCodeAt(0))

		// verifica assinatura do payload
		const valid = await verifyServerSignature(signatureBytes, payloadBytes)

		if (!valid) {
			throw new Error("Servidor não autenticado")
		}

		// agora sim, payload confiável
		const payload = JSON.parse(new TextDecoder().decode(payloadBytes))

		const { serverPublicKey, salt } = payload

		sessionId = data.sessionId

		// continua o fluxo normal
		const importedServerKey = await importServerPublicKey(serverPublicKey)
		const sharedSecret = await generateEphemeralSecret(clientKeys.privateKey, importedServerKey)

		symmetricKey = await deriveSymmetricKey(sharedSecret, salt)
	})()

	await handshakePromise
}

function joinChat() {
	const usernameInput = document.getElementById("username-input")
	username = usernameInput.value.trim()

	if (!username) {
		alert("Please enter a username")
		return
	}

	// Hide login section and show chat section
	document.getElementById("login-section").style.display = "none"
	document.getElementById("chat-section").style.display = "flex"

	// Use setTimeout to ensure DOM is ready before processing
	setTimeout(() => {
		// Focus on message input
		document.getElementById("message-input").focus()
	}, 0)
}

document.addEventListener("DOMContentLoaded", () => {
	const joinBtn = document.getElementById("join-btn")
	const usernameInput = document.getElementById("username-input")
	const statusDot = document.getElementById("status-dot")
	const statusText = document.getElementById("status-text")
	const chatContainer = document.getElementById("chat-container")

	const disconnectBtn = document.getElementById("disconnect-btn")

	// Join button click
	joinBtn.addEventListener("click", joinChat)

	// Disconnect button click
	disconnectBtn.addEventListener("click", () => {
		// Reset state
		window.location.reload()
	})

	// Enter key in username input
	usernameInput.addEventListener("keypress", (e) => {
		if (e.key === "Enter") {
			joinChat()
		}
	})

	// WebSocket open
	document.body.addEventListener("htmx:wsOpen", async () => {
		await ensureHandshake()
		console.log("WebSocket connected")
		statusDot.classList.remove("disconnected")
		statusDot.classList.add("connected")
		statusText.textContent = "Connected"
		disconnectBtn.style.display = "block"
	})

	// WebSocket closed
	document.body.addEventListener("htmx:wsClose", () => {
		console.log("WebSocket disconnected")
		statusDot.classList.remove("connected")
		statusDot.classList.add("disconnected")
		statusText.textContent = "Disconnected"
	})

	// WebSocket error
	document.body.addEventListener("htmx:wsError", (event) => {
		console.error("WebSocket error:", event)
		statusDot.classList.remove("connected")
		statusDot.classList.add("disconnected")
		statusText.textContent = "Disconnected"
	})

	// Encrypt messages right before htmx sends them over the socket
	chatContainer.addEventListener("htmx:wsConfigSend", async (event) => {
		try {
			event.preventDefault()

			htmx.trigger("#message-form", "htmx:abort")

			if (!symmetricKey) {
				throw new Error("Symmetric key unavailable")
			}

			const input = document.getElementById("message-input")
			const content = input.value.trim()

			if (!content) return

			// Optimistic UI update
			appendMessage({
				username: username,
				content: content,
			})

			// Clear input
			input.value = ""

			const payload = JSON.stringify({
				username: username,
				nonce: generateNonce(12),
				content: content,
			})

			const { ciphertext, iv } = await encryptWithAesGcm(symmetricKey, payload)
			event.detail.socketWrapper.sendImmediately(
				JSON.stringify({
					sessionId,
					content: ciphertext,
					iv,
				}),
			)
		} catch (err) {
			console.error("Failed to encrypt outgoing message", err)
		}
	})

	document.body.addEventListener("htmx:wsAfterMessage", async (event) => {
		try {
			if (!symmetricKey) return

			const incoming = JSON.parse(event.detail.message)

			if (!incoming.content || !incoming.iv) return

			const plaintext = await decryptWithAesGcm(symmetricKey, incoming.content, incoming.iv)

			const parsed = JSON.parse(plaintext)
			appendMessage(parsed)

			event.detail.shouldSwap = false
		} catch (err) {
			console.error("Failed to decrypt incoming message", err)
		}
	})
})
