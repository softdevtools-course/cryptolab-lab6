import { encodeBase64url, decodeBase64url } from './personal-keys.js';

const pss = { name: 'RSA-PSS', saltLength: 32 };
const data = (text) => new TextEncoder().encode(text);

export async function signPersonalText(keys, text, subtle = globalThis.crypto?.subtle) {
  const signature = await subtle.sign(pss, keys.signingPrivateKey, data(text));
  return {
    signature: encodeBase64url(signature),
    validForCertificateKey: await subtle.verify(pss, keys.signingPublicKey, signature, data(text)),
  };
}

export async function signTemporaryText(keys, text, subtle = globalThis.crypto?.subtle) {
  const temporary = await subtle.generateKey({
    name: 'RSA-PSS', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
  }, false, ['sign', 'verify']);
  const signature = await subtle.sign(pss, temporary.privateKey, data(text));
  return {
    spki: encodeBase64url(await subtle.exportKey('spki', temporary.publicKey)),
    signature: encodeBase64url(signature),
    validForTemporaryKey: await subtle.verify(pss, temporary.publicKey, signature, data(text)),
    validForCertificateKey: await subtle.verify(pss, keys.signingPublicKey, signature, data(text)),
  };
}

export function changeOneCharacter(text) {
  const characters = [...text];
  if (!characters.length) throw new Error('Текст задания пуст.');
  characters[characters.length - 1] = characters[characters.length - 1] === 'X' ? 'Y' : 'X';
  return characters.join('');
}

export async function checkAlteredText(keys, original, altered, signature, subtle = globalThis.crypto?.subtle) {
  const before = [...original];
  const after = [...altered];
  if (before.length !== after.length || before.filter((letter, index) => letter !== after[index]).length !== 1) {
    throw new Error('Измените ровно один символ текста.');
  }
  const bytes = decodeBase64url(signature);
  return {
    originalValid: await subtle.verify(pss, keys.signingPublicKey, bytes, data(original)),
    alteredValid: await subtle.verify(pss, keys.signingPublicKey, bytes, data(altered)),
  };
}
