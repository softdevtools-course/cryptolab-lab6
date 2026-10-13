const rsaParameters = (name) => ({
  name,
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-256',
});

export function encodeBase64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Некорректный шифротекст задания.');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export async function generatePersonalKeys(subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('Web Crypto недоступен. Откройте страницу на localhost.');
  const encryption = await subtle.generateKey(rsaParameters('RSA-OAEP'), false, ['encrypt', 'decrypt']);
  const signing = await subtle.generateKey(rsaParameters('RSA-PSS'), false, ['sign', 'verify']);
  return {
    encryptionPrivateKey: encryption.privateKey,
    encryptionPublicKey: encryption.publicKey,
    signingPrivateKey: signing.privateKey,
    signingPublicKey: signing.publicKey,
    encryptionSpki: encodeBase64url(await subtle.exportKey('spki', encryption.publicKey)),
    signingSpki: encodeBase64url(await subtle.exportKey('spki', signing.publicKey)),
  };
}

export async function provePersonalKeys(keys, challenge, subtle = globalThis.crypto?.subtle) {
  const plaintext = await subtle.decrypt(
    { name: 'RSA-OAEP' }, keys.encryptionPrivateKey, decodeBase64url(challenge.ciphertext),
  );
  const signature = await subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 }, keys.signingPrivateKey,
    new TextEncoder().encode(challenge.signing_text),
  );
  return {
    answer: new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
    signature: encodeBase64url(signature),
  };
}
