const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Gera um par de chaves efêmeras (pública/privada)
 * @returns {Object} Objeto contendo privateKey e publicKey em formato PEM
 */
function generateEphemeralKey() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return {
        privateKey,
        publicKey,
        createdAt: new Date().toISOString()
    };
}

/**
 * Encrypts data using the server's public certificate (RSA)
 * @param {string} data - The data to encrypt
 * @returns {string} Base64 encoded encrypted data
 */
function encryptWithServerCert(data) {
    const certificatePath = path.join(__dirname, 'cert.pem');
    const cert = fs.readFileSync(certificatePath, 'utf8');

    // Extract the public key from the certificate
    const publicKey = crypto.createPublicKey({
        key: cert,
        format: 'pem'
    });

    // Encrypt the data using RSA-PKCS1v1.5 (matching server's DecryptPKCS1v15)
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        },
        buffer
    );

    return encrypted.toString('base64');
}

/**
 * Assina dados usando o certificado autoassinado
 */
function signData(data) {
    const certificatePath = path.join(__dirname, 'cert.pem');
    const publicKey = fs.readFileSync(certificatePath, 'utf8');

    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();

    const signature = sign.sign(publicKey, 'base64');
    return signature;
}

module.exports = {
    generateEphemeralKey,
    signData,
    encryptWithServerCert
};

