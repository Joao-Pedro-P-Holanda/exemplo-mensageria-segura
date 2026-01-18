import {
	generateKeyPair,
	generateEphemeralSecret,
	importServerPublicKey,
	deriveSessionKeys,
	encryptWithAesGcm,
	decryptWithAesGcm,
	encryptWithServerCert,
	verifyServerSignature,
} from "./integrity"
import { generateNonce } from "./utils"
import "./styles.css"

let username = ""
let keyC2S = null
let keyS2C = null
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
	if (keyC2S && keyS2C) return
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
				Authorization: "Basic " + btoa(username + ":"),
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

		const keys = await deriveSessionKeys(sharedSecret, salt)
		keyC2S = keys.keyC2S
		keyS2C = keys.keyS2C
	})()

	await handshakePromise
}

async function joinChat() {
	const usernameInput = document.getElementById("username-input")
	username = usernameInput.value.trim()

	if (!username) {
		alert("Please enter a username")
		return
	}

	try {
		await ensureHandshake()
	} catch (err) {
		console.error(err)
		alert("Handshake failed: " + err.message)
		return
	}

	// Sync login recipient to main recipient input
	const loginRecipientObj = document.getElementById("recipient-input-login")
	const recipientInput = document.getElementById("recipient-input")
	if (loginRecipientObj && recipientInput) {
		recipientInput.value = loginRecipientObj.value.trim()
	}

	// Hide login section and show chat section
	document.getElementById("login-section").style.display = "none"
	document.getElementById("chat-section").style.display = "flex"

	// Connect WebSocket
	const chatContainer = document.getElementById("chat-container")
	chatContainer.setAttribute("hx-ext", "ws")
	chatContainer.setAttribute("ws-connect", `ws://localhost:8080/ws?clientId=${encodeURIComponent(username)}&sessionId=${sessionId}`)
	htmx.process(chatContainer)

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

			if (!keyC2S) {
				throw new Error("Client-Server key unavailable")
			}

			const input = document.getElementById("message-input")
			const content = input.value.trim()

			if (!content) return

			const recipient = document.getElementById("recipient-input").value.trim()


			// If I send a message:
			// - Broadcast: Show it.
			// - Private: Show it only if I'm viewing that private chat (which I am, by definition of input).
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

			const { ciphertext, iv } = await encryptWithAesGcm(keyC2S, payload)
			event.detail.socketWrapper.sendImmediately(
				JSON.stringify({
					sessionId,
					recipientId: recipient,
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
			if (!keyS2C) return

			const incoming = JSON.parse(event.detail.message)

			if (!incoming.content || !incoming.iv) return

			// Filtering
			const activeRecipient = document.getElementById("recipient-input").value.trim()

			// incoming.recipientId is empty for broadcast, or set to MyID for private messages.
			// incoming.senderId is the sender.

			if (activeRecipient === "") {
				// Broadcast Mode:
				// ONLY show if it is a broadcast message (recipientId is empty).
				if (incoming.recipientId !== "") return
			} else {
				// Private Mode:
				// ONLY show if it is a private message meant for ME (recipientId !== "")
				// AND it is from the person I am talking to (senderId === activeRecipient)

				// Case 1: Message is a Broadcast. I am in Private Mode. -> HIDE
				if (incoming.recipientId === "") return

				// Case 2: Message is Private.
				// Is it from the person I'm looking at?
				if (incoming.senderId !== activeRecipient) return
			}

			const plaintext = await decryptWithAesGcm(keyS2C, incoming.content, incoming.iv)

			const parsed = JSON.parse(plaintext)
			appendMessage(parsed)

			event.detail.shouldSwap = false
		} catch (err) {
			console.error("Failed to decrypt incoming message", err)
		}
	})
})
