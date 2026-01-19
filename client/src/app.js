import {
	generateKeyPair,
	generateEphemeralSecret,
	importServerPublicKey,
	deriveSessionKeys,
	encryptWithAesGcm,
	decryptWithAesGcm,
	encryptWithServerCert,
	verifyServerSignature,
	buildAad,
} from "./integrity"
import { generateNonce } from "./utils"
import "./styles.css"

let username = ""
let keyC2S = null
let keyS2C = null
let sessionId = ""
let clientKeys = null
let currentHandshakeId = 0

// Sequence numbers
let sendSeq = 1
let recvSeq = 0

// WebSocket
let currentSocket = null

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

async function performHandshake() {
	const keys = await generateKeyPair()
	const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey)

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

	const payloadBytes = Uint8Array.from(atob(data.payload), (c) => c.charCodeAt(0))
	const signatureBytes = Uint8Array.from(atob(data.signature), (c) => c.charCodeAt(0))

	const valid = await verifyServerSignature(signatureBytes, payloadBytes)

	if (!valid) {
		throw new Error("Servidor não autenticado")
	}

	const payload = JSON.parse(new TextDecoder().decode(payloadBytes))
	const { serverPublicKey, salt } = payload

	const importedServerKey = await importServerPublicKey(serverPublicKey)
	const sharedSecret = await generateEphemeralSecret(keys.privateKey, importedServerKey)

	const sessionKeys = await deriveSessionKeys(sharedSecret, salt)

	return {
		sessionId: data.sessionId,
		keyC2S: sessionKeys.keyC2S,
		keyS2C: sessionKeys.keyS2C,
	}
}

async function joinChat() {
	const usernameInput = document.getElementById("username-input")
	username = usernameInput.value.trim()

	if (!username) {
		alert("Please enter a username")
		return
	}

	// RESET STATE FOR NEW SESSION
	keyC2S = null
	keyS2C = null
	sessionId = ""
	sendSeq = 1
	recvSeq = 0

	const myHandshakeId = ++currentHandshakeId
	console.log(`[JoinChat] Starting handshake ${myHandshakeId}`)

	try {
		const result = await performHandshake()
		console.log(`[JoinChat] Handshake ${myHandshakeId} completed. Result Session: ${result.sessionId}. Current Global: ${currentHandshakeId}`)

		// Race condition check: if another Join started, abort this one
		if (myHandshakeId !== currentHandshakeId) {
			console.warn(`[JoinChat] Aborting handshake ${myHandshakeId} because current is ${currentHandshakeId}`)
			return
		}

		sessionId = result.sessionId
		keyC2S = result.keyC2S
		keyS2C = result.keyS2C
		console.log(`[JoinChat] Session updated to ${sessionId} by handshake ${myHandshakeId}`)
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

	// Connect Native WebSocket
	if (currentSocket) {
		console.log("[JoinChat] Closing existing socket")
		currentSocket.close()
		currentSocket = null
	}

	const wsUrl = `ws://localhost:8080/ws?clientId=${encodeURIComponent(username)}&sessionId=${sessionId}`
	console.log(`[JoinChat] Connecting Native WS to ${wsUrl}`)

	currentSocket = new WebSocket(wsUrl)
	setupSocketHandlers(currentSocket)

	// Use setTimeout to ensure DOM is ready before processing
	setTimeout(() => {
		// Focus on message input
		document.getElementById("message-input").focus()
	}, 0)
}

function setupSocketHandlers(socket) {
	const statusDot = document.getElementById("status-dot")
	const statusText = document.getElementById("status-text")
	const disconnectBtn = document.getElementById("disconnect-btn")

	socket.onopen = () => {
		console.log("WebSocket connected")
		statusDot.classList.remove("disconnected")
		statusDot.classList.add("connected")
		statusText.textContent = "Connected"
		disconnectBtn.style.display = "block"
	}

	socket.onclose = () => {
		console.log("WebSocket disconnected")
		statusDot.classList.remove("connected")
		statusDot.classList.add("disconnected")
		statusText.textContent = "Disconnected"
	}

	socket.onerror = (error) => {
		console.error("WebSocket error:", error)
		statusDot.classList.remove("connected")
		statusDot.classList.add("disconnected")
		statusText.textContent = "Disconnected"
	}

	socket.onmessage = async (event) => {
		try {
			if (!keyS2C) return

			const incoming = JSON.parse(event.data)

			if (!incoming.content || !incoming.iv) return

			// Filtering
			const activeRecipient = document.getElementById("recipient-input").value.trim()

			if (activeRecipient === "") {
				if (incoming.recipientId !== "") return
			} else {
				if (incoming.recipientId === "") return
				if (incoming.senderId !== activeRecipient) return
			}

			// Sequence and AAD
			const seq = incoming.seqNo
			if (seq < recvSeq) {
				console.warn("Replay or out-of-order message", { expected: recvSeq, got: seq })
				return
			}
			recvSeq = seq + 1

			const aad = buildAad(incoming.senderId, incoming.recipientId, seq)
			const plaintext = await decryptWithAesGcm(keyS2C, incoming.content, incoming.iv, aad)

			const parsed = JSON.parse(plaintext)
			appendMessage(parsed)
		} catch (err) {
			console.error("Failed to decrypt incoming message", err)
		}
	}
}

async function sendMessage(event) {
	event.preventDefault()

	if (!currentSocket || currentSocket.readyState !== WebSocket.OPEN) {
		console.error("WebSocket not connected")
		return
	}

	if (!keyC2S) {
		console.error("Client-Server key unavailable")
		return
	}

	const input = document.getElementById("message-input")
	const content = input.value.trim()

	if (!content) return

	const recipient = document.getElementById("recipient-input").value.trim()

	// Optimistic update
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

	const seq = sendSeq++
	const aad = buildAad(username, recipient, seq)

	try {
		const { ciphertext, iv } = await encryptWithAesGcm(keyC2S, payload, aad)

		const messageFrame = JSON.stringify({
			sessionId: parseInt(sessionId),
			recipientId: recipient,
			senderId: username,
			content: ciphertext,
			seqNo: seq,
			iv,
		})

		currentSocket.send(messageFrame)
	} catch (err) {
		console.error("Failed to encrypt outgoing message", err)
	}
}

document.addEventListener("DOMContentLoaded", () => {
	const joinBtn = document.getElementById("join-btn")
	const usernameInput = document.getElementById("username-input")
	const disconnectBtn = document.getElementById("disconnect-btn")
	const messageForm = document.getElementById("message-form")

	// Join button click
	joinBtn.addEventListener("click", joinChat)

	// Disconnect button click
	disconnectBtn.addEventListener("click", () => {
		if (currentSocket) {
			currentSocket.close()
		}
		window.location.reload()
	})

	// Enter key in username input
	usernameInput.addEventListener("keypress", (e) => {
		if (e.key === "Enter") {
			joinChat()
		}
	})

	// Handle message submission manually
	messageForm.addEventListener("submit", sendMessage)
})
