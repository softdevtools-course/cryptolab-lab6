import { encodeBase64url, decodeBase64url } from './personal-keys.js';

export const ALGORITHM = 'AES-256-GCM+RSA-OAEP-SHA256';

export function packageAad(packet) {
  const fields = {
    version: packet.version,
    package_id: packet.package_id,
    lab_id: packet.lab_id,
    sender_actor_id: packet.sender_actor_id,
    recipient_actor_id: packet.recipient_actor_id,
    recipient_certificate_serial: packet.recipient_certificate_serial,
    algorithm: packet.algorithm,
  };
  return new TextEncoder().encode(JSON.stringify(fields));
}

export async function encryptPackage(text, challenge, recipientSpki, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('Web Crypto недоступен.');
  const recipientKey = await subtle.importKey('spki', decodeBase64url(recipientSpki),
    { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const aes = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawKey = await subtle.exportKey('raw', aes);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const packet = {
    version: 1, package_id: challenge.package_id, lab_id: 6,
    sender_actor_id: challenge.sender_actor_id, recipient_actor_id: challenge.recipient_actor_id,
    recipient_certificate_serial: challenge.recipient_certificate_serial,
    algorithm: ALGORITHM,
    wrapped_key: encodeBase64url(await subtle.encrypt({ name: 'RSA-OAEP' }, recipientKey, rawKey)),
    iv: encodeBase64url(iv),
    ciphertext: '', created_at: new Date().toISOString(),
  };
  packet.ciphertext = encodeBase64url(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: packageAad(packet), tagLength: 128 },
    aes, new TextEncoder().encode(text),
  ));
  return packet;
}

export async function decryptPackage(packet, privateKey, subtle = globalThis.crypto?.subtle) {
  if (packet.version !== 1 || packet.lab_id !== 6 || packet.algorithm !== ALGORITHM) {
    throw new Error('Неподдерживаемая версия или алгоритм пакета.');
  }
  const rawKey = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, decodeBase64url(packet.wrapped_key));
  const aes = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const clear = await subtle.decrypt({ name: 'AES-GCM', iv: decodeBase64url(packet.iv),
    additionalData: packageAad(packet), tagLength: 128 }, aes, decodeBase64url(packet.ciphertext));
  return new TextDecoder('utf-8', { fatal: true }).decode(clear);
}
