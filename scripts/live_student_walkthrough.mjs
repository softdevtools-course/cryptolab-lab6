// A one-off, live localhost walkthrough using the same Web Crypto modules as the page.
// Run with the CA fingerprint received separately from the application.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { decryptRsaOaepText } from '../web/crypto.js';
import { generatePersonalKeys, provePersonalKeys } from '../web/personal-keys.js';
import { signPersonalText, signTemporaryText, checkAlteredText, changeOneCharacter } from '../web/signature.js';
import { encryptPackage, decryptPackage } from '../web/packages.js';

const base = process.env.CRYPTOLAB_BASE_URL || 'http://127.0.0.1:18766';
const authToken = process.env.CRYPTOLAB_AUTH_TOKEN;
const independentFingerprint = process.argv[2]?.replaceAll(':', '').toLowerCase();
assert.match(independentFingerprint || '', /^[a-f0-9]{64}$/, 'Pass the independent CA SHA-256 fingerprint');
let cookie = '';

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}), ...(cookie ? { Cookie: cookie } : {}),
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    ...(options.method === 'POST' ? { Origin: new URL(base).origin } : {}) };
  const response = await fetch(base + path, { ...options, headers });
  if (!cookie && response.headers.get('set-cookie')) cookie = response.headers.get('set-cookie').split(';')[0];
  const body = await response.json();
  return { status: response.status, body };
}

async function api(path, options = {}) {
  const response = await request(path, options);
  assert.equal(response.status, 200, `${path}: ${JSON.stringify(response.body)}`);
  return response.body;
}

function post(path, value = {}) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
}

async function progress(expected, label) {
  const state = await api('/api/state');
  assert.equal(state.steps_done, expected, label);
  console.log(`${expected}/6 · ${label}`);
  return state;
}

const subtle = crypto.subtle;
const [trainingKey, wrongKey, ciphertext] = await Promise.all(
  ['training-key.pem', 'wrong-key.pem', 'ciphertext.txt'].map(async (name) => {
    const response = await fetch(`${base}/examples/${name}`, {
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
    });
    assert.equal(response.status, 200);
    return (await response.text()).trim();
  }),
);
assert.match(await decryptRsaOaepText(trainingKey, ciphertext, subtle), /^Ключ подходит:/);
await assert.rejects(decryptRsaOaepText(wrongKey, ciphertext, subtle));
const prep = await post('/api/challenges');
const prepAnswer = await decryptRsaOaepText(trainingKey, prep.ciphertext, subtle);
assert.equal((await post(`/api/challenges/${prep.challenge_id}/verify`, { answer: prepAnswer })).verified, true);
await progress(1, 'учебное расшифрование, включая отказ другого ключа');

const keys = await generatePersonalKeys(subtle);
assert.equal(keys.encryptionPrivateKey.extractable, false);
assert.equal(keys.signingPrivateKey.extractable, false);
const keyChallenge = await post('/api/key-proofs', {
  encryption_spki: keys.encryptionSpki, signing_spki: keys.signingSpki,
});
const keyProof = await provePersonalKeys(keys, keyChallenge, subtle);
assert.equal((await post(`/api/key-proofs/${keyChallenge.challenge_id}/verify`, keyProof)).verified, true);
await progress(2, 'две личные пары и подтверждение владения');

const root = await api('/api/ca');
assert.equal(root.fingerprint_sha256.replaceAll(':', ''), independentFingerprint);
const issued = await post('/api/certificates');
const rootX509 = new X509Certificate(root.certificate_pem);
for (const purpose of ['encryption', 'signature']) {
  assert.equal(new X509Certificate(issued[purpose].certificate_pem).verify(rootX509.publicKey), true);
}
assert.equal((await post('/api/certificates/verify', { ca_fingerprint_sha256: independentFingerprint })).verified, true);
await progress(3, 'два сертификата и независимый отпечаток CA');

const signatureChallenge = await post('/api/signature-challenges');
const own = await signPersonalText(keys, signatureChallenge.text, subtle);
const temporary = await signTemporaryText(keys, signatureChallenge.text, subtle);
const alteredText = changeOneCharacter(signatureChallenge.text);
const changed = await checkAlteredText(keys, signatureChallenge.text, alteredText, own.signature, subtle);
assert.equal(own.validForCertificateKey, true);
assert.equal(temporary.validForTemporaryKey, true);
assert.equal(temporary.validForCertificateKey, false);
assert.equal(changed.originalValid, true);
assert.equal(changed.alteredValid, false);
const signatureCheck = await post(`/api/signature-challenges/${signatureChallenge.challenge_id}/verify`, {
  own_signature: own.signature, temporary_spki: temporary.spki,
  temporary_signature: temporary.signature, altered_text: alteredText,
});
assert.equal(signatureCheck.verified, true);
await progress(4, 'верная подпись, другой ключ и изменённый текст');

const service = await api('/api/service-certificate');
assert.equal(new X509Certificate(service.certificate_pem).verify(rootX509.publicKey), true);
const outboundChallenge = await post('/api/outbound-packages/challenges');
const text = 'Проверяю учебный зашифрованный пакет';
const outbound = await encryptPackage(text, outboundChallenge, service.encryption_spki, subtle);
assert.equal(JSON.stringify(outbound).includes(text), false);
const outboundUrl = `/api/outbound-packages/${outbound.package_id}/verify`;
assert.equal((await request(outboundUrl, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ package: { ...outbound, recipient_actor_id: 'student:other' } }),
})).status, 422);
assert.equal((await post(outboundUrl, { package: outbound })).verified, true);
await progress(5, 'пакет серверу и отказ при подмене получателя');

const inbound = await post('/api/inbound-packages');
assert.equal(inbound.package.recipient_actor_id, (await api('/api/state')).actor_id);
assert.equal(inbound.package.recipient_certificate_serial, issued.encryption.serial_number);
const inboundAnswer = await decryptPackage(inbound.package, keys.encryptionPrivateKey, subtle);
const inboundUrl = `/api/inbound-packages/${inbound.package.package_id}/verify`;
assert.equal((await post(inboundUrl, { answer: 'wrong' })).verified, false);
assert.equal((await post(inboundUrl, { answer: inboundAnswer })).verified, true);
await progress(6, 'ответный пакет, расшифрование личным ключом');

assert.deepEqual(await post('/api/student', { surname: 'Тестовый', given_name: 'Студент', group: 'DEMO' }),
  { surname: 'Тестовый', given_name: 'Студент', group: 'DEMO' });
const firstSubmission = await post('/api/submissions');
const secondSubmission = await post('/api/submissions');
assert.equal(firstSubmission.status, 'Ожидает проверки');
assert.equal(firstSubmission.already_submitted, false);
assert.equal(secondSubmission.already_submitted, true);
assert.equal(firstSubmission.submitted_at, secondSubmission.submitted_at);
console.log('Сдача · Ожидает проверки; повторная отправка не создала новую запись');
