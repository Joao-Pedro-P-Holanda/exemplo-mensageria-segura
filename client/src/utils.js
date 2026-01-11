/*Source: https://jsgenerator.com/blog/secure-random-string-generator-javascript*/
export function generateNonce(numBytes) {

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const alphabetLength = alphabet.length;
  const randomValues = new Uint8Array(numBytes);

  window.crypto.getRandomValues(randomValues);

  let token = '';

  for (let index = 0; index < randomValues.length; index += 1) {
    const charIndex = randomValues[index] % alphabetLength;
    token += alphabet[charIndex];
  }

  return token;
}
