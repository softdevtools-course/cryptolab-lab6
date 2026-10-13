export async function decryptRsaOaepText(pem, ciphertextBase64url, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('Web Crypto недоступен. Откройте страницу на localhost.');

  const match = pem.trim().match(/^-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----$/);
  if (!match) throw new Error('Нужен закрытый ключ PKCS#8 в PEM.');

  const der = Uint8Array.from(atob(match[1].replace(/\s/g, '')), (character) => character.charCodeAt(0));
  const encoded = ciphertextBase64url.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('Шифротекст должен быть в base64url.');
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - encoded.length % 4) % 4);
  const ciphertext = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));

  const key = await subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const plaintext = await subtle.decrypt({ name: 'RSA-OAEP' }, key, ciphertext);
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
}
