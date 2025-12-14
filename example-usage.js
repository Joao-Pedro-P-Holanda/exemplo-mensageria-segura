const { generateEphemeralKey, signData, verifySignature, encryptWithServerCert } = require('./client/integrity');

// Exemplo 1: Gerar chave efêmera
console.log('=== Gerando Chave Efêmera ===');
const ephemeralKey = generateEphemeralKey();
console.log('Chave Privada Efêmera:', ephemeralKey.privateKey.substring(0, 50) + '...');
console.log('Chave Pública Efêmera:', ephemeralKey.publicKey.substring(0, 50) + '...');
console.log('Criada em:', ephemeralKey.createdAt);
console.log('');

// Exemplo 2: Assinar dados
console.log('=== Assinando Dados ===');
const dataToSign = 'Mensagem importante para ser assinada';
const signature = signData(dataToSign);
console.log('Dados:', dataToSign);
console.log('Assinatura:', signature);
console.log('');

// Exemplo 4: Criptografar dados e verificar com o servidor
console.log('=== Criptografando e Verificando com Servidor ===');
const dataToEncrypt = 'Mensagem secreta para o servidor';
const encryptedData = encryptWithServerCert(dataToEncrypt);
console.log('Dados originais:', dataToEncrypt);
console.log('Dados criptografados (base64):', encryptedData.substring(0, 50) + '...');

// Enviar para o endpoint /verify
(async () => {
    try {
        const response = await fetch('http://localhost:8080/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                encryptedData: encryptedData
            })
        });

        const result = await response.json();
        console.log('\nResposta do servidor:');
        console.log('Sucesso:', result.success);
        if (result.success) {
            console.log('Dados descriptografados:', result.decryptedData);
            console.log('Dados correspondem?', result.decryptedData === dataToEncrypt);
        } else {
            console.log('Erro:', result.error);
        }
    } catch (error) {
        console.error('Erro ao conectar com o servidor:', error.message);
        console.log('\nDica: Certifique-se de que o servidor está rodando na porta 8080');
    }
})();



