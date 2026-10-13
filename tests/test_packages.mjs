import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encryptPackage, decryptPackage, packageAad } from '../web/packages.js';

test('browser builds and opens hybrid v1 package; AAD rejects changed metadata', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
  const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey)).toString('base64url');
  const challenge = { package_id: 'abc', sender_actor_id: 'student:abc',
    recipient_actor_id: 'service:cryptolab', recipient_certificate_serial: 'a1' };
  const packet = await encryptPackage('Привет', challenge, spki);
  assert.equal(packet.version, 1);
  assert.equal(packet.lab_id, 6);
  assert.equal(await decryptPackage(packet, pair.privateKey), 'Привет');
  assert.equal(new TextDecoder().decode(packageAad(packet)),
    '{"version":1,"package_id":"abc","lab_id":6,"sender_actor_id":"student:abc","recipient_actor_id":"service:cryptolab","recipient_certificate_serial":"a1","algorithm":"AES-256-GCM+RSA-OAEP-SHA256"}');
  await assert.rejects(decryptPackage({ ...packet, recipient_actor_id: 'student:other' }, pair.privateKey));
  await assert.rejects(decryptPackage({ ...packet, ciphertext: 'AAAA' }, pair.privateKey));
});
