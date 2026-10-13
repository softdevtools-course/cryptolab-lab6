import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { decryptRsaOaepText } from '../web/crypto.js';
import { generatePersonalKeys, provePersonalKeys } from '../web/personal-keys.js';
import { signPersonalText, signTemporaryText, checkAlteredText, changeOneCharacter } from '../web/signature.js';

const examples = new URL('../examples/', import.meta.url);
const key = readFileSync(new URL('training-key.pem', examples), 'utf8');
const wrongKey = readFileSync(new URL('wrong-key.pem', examples), 'utf8');
const ciphertext = readFileSync(new URL('ciphertext.txt', examples), 'utf8').trim();

test('browser crypto decrypts the published example', async () => {
  const plaintext = await decryptRsaOaepText(key, ciphertext, webcrypto.subtle);
  assert.match(plaintext, /^Ключ подходит:/);
});

test('browser crypto rejects a different key', async () => {
  await assert.rejects(decryptRsaOaepText(wrongKey, ciphertext, webcrypto.subtle));
});

test('browser crypto rejects changed ciphertext', async () => {
  const changed = `${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`;
  await assert.rejects(decryptRsaOaepText(key, changed, webcrypto.subtle));
});

test('browser crypto rejects malformed PEM', async () => {
  await assert.rejects(decryptRsaOaepText('not a PEM key', ciphertext, webcrypto.subtle), /PKCS#8/);
});

test('personal private keys are distinct and nonextractable', async () => {
  const keys = await generatePersonalKeys(webcrypto.subtle);
  assert.equal(keys.encryptionPrivateKey.extractable, false);
  assert.equal(keys.signingPrivateKey.extractable, false);
  assert.notEqual(keys.encryptionSpki, keys.signingSpki);
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', keys.encryptionPrivateKey));
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', keys.signingPrivateKey));
});

test('personal keys decrypt and sign one-time proof', async () => {
  const keys = await generatePersonalKeys(webcrypto.subtle);
  const answer = 'one-time-answer';
  const signingText = 'CryptoLab proof 123';
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, keys.encryptionPublicKey, new TextEncoder().encode(answer),
  );
  const proof = await provePersonalKeys(keys, {
    ciphertext: Buffer.from(ciphertext).toString('base64url'), signing_text: signingText,
  }, webcrypto.subtle);
  assert.equal(proof.answer, answer);
  assert.equal(await webcrypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 }, keys.signingPublicKey,
    Buffer.from(proof.signature, 'base64url'), new TextEncoder().encode(signingText),
  ), true);
});

test('browser shows valid signature, other key, and changed text as distinct outcomes', async () => {
  const keys = await generatePersonalKeys(webcrypto.subtle);
  const text = 'CryptoLab · подпишите одноразовый текст abc123';
  const own = await signPersonalText(keys, text, webcrypto.subtle);
  assert.equal(own.validForCertificateKey, true);
  const temporary = await signTemporaryText(keys, text, webcrypto.subtle);
  assert.equal(temporary.validForTemporaryKey, true);
  assert.equal(temporary.validForCertificateKey, false);
  assert.notEqual(temporary.spki, keys.signingSpki);
  const altered = changeOneCharacter(text);
  assert.equal(altered.length, text.length);
  assert.equal([...altered].filter((letter, index) => letter !== [...text][index]).length, 1);
  const changed = await checkAlteredText(keys, text, altered, own.signature, webcrypto.subtle);
  assert.equal(changed.originalValid, true);
  assert.equal(changed.alteredValid, false);
  await assert.rejects(checkAlteredText(keys, text, text, own.signature, webcrypto.subtle), /один символ/);
});
