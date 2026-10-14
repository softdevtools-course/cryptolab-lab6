import { decryptRsaOaepText } from '/crypto.js';
import { generatePersonalKeys, provePersonalKeys } from '/personal-keys.js';
import { loadKeys, saveKeys } from '/key-store.js';
import { signPersonalText, signTemporaryText, checkAlteredText, changeOneCharacter } from '/signature.js';
import { encryptPackage, decryptPackage } from '/packages.js';

const field = (id) => document.getElementById(id);
const keyInput = field('keyInput');
const cipherInput = field('cipherInput');
const challengeCipher = field('challengeCipher');
const answerInput = field('answerInput');
let challengeId = null;
let exampleSolved = false;
let wrongKeyObserved = false;
let inputVersion = 0;
let actorId = null;
let personalKeys = null;
let keyChallenge = null;
let keysVerified = false;
let certificatesIssued = false;
let certificatesVerified = false;
let certificatesCurrent = false;
let certificatesReady = false;
let signatureVerified = false;
let signatureChallenge = null;
let ownExerciseSignature = null;
let temporaryExercise = null;
let changedExerciseChecked = false;
let outboundChallenge = null;
let serviceCertificate = null;
let outboundPackage = null;
let inboundPackage = null;
let studentDirty = false;

const examples = Promise.all(['training-key.pem', 'wrong-key.pem', 'ciphertext.txt'].map(async (name) => {
  const response = await fetch(`/examples/${name}`);
  if (!response.ok) throw new Error('Не удалось загрузить учебные файлы.');
  return (await response.text()).trim();
}));

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(Array.isArray(body.detail)
    ? body.detail.map((item) => item.msg.replace(/^Value error, /, '')).join('; ')
    : body.detail || 'Сервер не ответил.');
  return body;
}

function result(id, message, kind = '') {
  const box = field(id);
  box.textContent = message;
  box.className = `result ${kind}`.trim();
}

function updateProgress(state) {
  field('progressBar').setAttribute('aria-valuenow', String(state.steps_done));
  field('progressFill').style.width = `${state.steps_done / state.steps_total * 100}%`;
  field('progressText').textContent = state.steps_done === 6
    ? 'Техническая часть выполнена'
    : state.inbound_verified ? 'Ответный пакет подтверждён'
    : state.outbound_verified ? 'Пакет серверу подтверждён · далее ответный пакет'
    : state.signature_verified
    ? 'Подпись подтверждена · далее пакет для сервера'
    : state.certificates_verified
    ? state.certificates_ready
      ? 'Сертификаты подтверждены · далее упражнение с подписью'
      : 'Шаг сертификатов засчитан · обновите сертификаты для продолжения'
    : state.keys_verified ? 'Личные ключи подтверждены · далее сертификаты'
    : state.completed ? 'Подготовительный шаг подтверждён · далее личные ключи'
      : 'Ожидается подготовительный шаг';
}

async function refreshState() {
  const state = await api('/api/state');
  actorId = state.actor_id;
  keysVerified = state.keys_verified;
  certificatesIssued = state.certificates_issued;
  certificatesVerified = state.certificates_verified;
  certificatesCurrent = state.certificates_current;
  certificatesReady = state.certificates_ready;
  signatureVerified = state.signature_verified;
  field('actorId').textContent = actorId;
  updateProgress(state);
  if (!studentDirty) {
    field('studentSurname').value = state.student?.surname || '';
    field('studentGivenName').value = state.student?.given_name || '';
    field('studentGroup').value = state.student?.group || '';
  }
  const studentLocked = !!state.submitted_at && !!state.student?.given_name;
  const existingDetailsLocked = !!state.submitted_at && !!state.student;
  field('studentSurname').disabled = existingDetailsLocked;
  field('studentGivenName').disabled = studentLocked;
  field('studentGroup').disabled = existingDetailsLocked;
  field('saveStudent').disabled = studentLocked;
  result('studentResult', studentLocked
    ? `Данные закреплены за сданной работой: ${state.student.surname} ${state.student.given_name}, ${state.student.group}.`
    : studentDirty ? 'Изменения ещё не сохранены.'
    : state.submitted_at && state.student ? 'Для уже отправленной работы добавьте имя и сохраните данные.'
    : state.student ? `Сохранено: ${state.student.surname} ${state.student.given_name}, ${state.student.group}.`
    : 'Укажите фамилию, имя и группу, затем сохраните их.', studentLocked || (!studentDirty && state.student && !state.submitted_at) ? 'success' : '');
  if (state.completed) {
    unlockChallenge();
    field('keysSection').classList.remove('locked');
    if (!personalKeys) {
      try { personalKeys = await loadKeys(actorId) || null; }
      catch (error) { result('keysResult', `Не удалось открыть хранилище ключей: ${error.message}`, 'error'); }
    }
    field('generateKeys').disabled = keysVerified || !!personalKeys;
    field('requestKeyProof').disabled = keysVerified || !personalKeys;
    if (keysVerified) {
      field('generateKeys').disabled = true;
      field('requestKeyProof').disabled = true;
      field('proveKeys').disabled = true;
      field('confirmKeys').disabled = true;
      result('keysResult', personalKeys
        ? 'Обе пары подтверждены сервером. Ключи найдены в этом браузере.'
        : 'Обе пары подтверждены, но закрытые ключи в этом браузере не найдены. Для дальнейшей работы понадобится сброс доступа.',
      personalKeys ? 'success' : 'error');
    } else if (personalKeys) {
      result('keysResult', 'Личные ключи найдены в этом браузере. Получите задания для проверки.');
    } else {
      result('keysResult', 'Создайте отдельные пары для шифрования и подписи.');
    }
  }
  if (keysVerified) {
    field('certificatesSection').classList.remove('locked');
    field('issueCertificates').disabled = certificatesCurrent;
    field('issueCertificates').textContent = certificatesIssued && !certificatesCurrent
      ? 'Получить новые сертификаты' : 'Получить сертификаты';
    field('verifyCertificates').disabled = !certificatesCurrent || certificatesReady;
    if (certificatesIssued) {
      const [issued, root] = await Promise.all([api('/api/certificates'), api('/api/ca')]);
      showCertificates(issued);
      showRoot(root);
      result('certificatesResult', !certificatesCurrent
        ? 'Срок этих сертификатов истёк. Получите новые сертификаты. Уже засчитанный шаг сохранён.'
        : certificatesReady
          ? 'Два сертификата и отпечаток корня подтверждены. Следующий шаг — подпись текста.'
          : 'Два сертификата получены. Сверьте отпечаток CA с независимым контрольным значением.',
      certificatesReady ? 'success' : '');
    } else {
      result('certificatesResult', 'Личные ключи подтверждены. Получите два сертификата от учебного CA.');
    }
  }
  if (certificatesReady) {
    field('signatureSection').classList.remove('locked');
    field('issueSignatureChallenge').disabled = signatureVerified || !personalKeys;
    if (signatureVerified) {
      field('signPersonalChallenge').disabled = true;
      field('signTemporaryChallenge').disabled = true;
      field('suggestChangedText').disabled = true;
      field('checkChangedText').disabled = true;
      field('verifySignatureExercise').disabled = true;
      result('signatureResult', 'Сервер проверил три опыта с подписью. Следующий шаг — зашифрованный пакет для сервера.', 'success');
    } else if (!personalKeys) {
      result('signatureResult', 'Закрытый ключ подписи не найден в этом браузере. Для опыта понадобится сброс доступа.', 'error');
    } else if (!signatureChallenge) {
      result('signatureResult', 'Получите одноразовый текст для трёх опытов.');
    }
  } else if (certificatesVerified) {
    result('signatureResult', 'Сертификаты нужно обновить и повторно подтвердить перед упражнением с подписью.');
  }
  if (signatureVerified) {
    field('outboundSection').classList.remove('locked');
    field('prepareOutbound').disabled = state.outbound_verified;
    if (state.outbound_verified) result('outboundResult', 'Сервер расшифровал и проверил ваш пакет.', 'success');
  }
  if (state.outbound_verified) {
    field('inboundSection').classList.remove('locked');
    field('requestInbound').disabled = state.inbound_verified || !personalKeys || !certificatesReady;
    if (state.inbound_verified) result('inboundResult', 'Ответный пакет расшифрован в браузере, секрет подтверждён сервером.', 'success');
    else if (!certificatesReady) result('inboundResult', 'Обновите и подтвердите сертификат шифрования перед получением пакета.', 'error');
  }
  if (state.steps_done === 6) {
    field('submissionSection').classList.remove('locked');
    field('submitLab').disabled = !!state.submitted_at || !state.student?.given_name || studentDirty;
    result('submissionResult', state.submitted_at
      ? `Ожидает проверки · отправлено ${new Date(state.submitted_at).toLocaleString('ru-RU')}${state.student?.given_name ? '' : ' · укажите фамилию, имя и группу для ведомости'}`
      : !state.student?.given_name || studentDirty ? 'Техническая часть выполнена. Сохраните фамилию, имя и группу перед отправкой.'
      : 'Техническая часть выполнена. Отправьте работу на проверку.', state.submitted_at ? 'success' : '');
  }
  return state;
}

function updateSignatureSubmit() {
  field('verifySignatureExercise').disabled = signatureVerified || !signatureChallenge
    || !ownExerciseSignature || !temporaryExercise || !changedExerciseChecked;
}

function showCertificates(issued) {
  for (const purpose of ['encryption', 'signature']) {
    const item = issued[purpose];
    const id = purpose === 'encryption' ? 'encryptionCertificate' : 'signatureCertificate';
    field(id).value = item.certificate_pem;
    field(`${id}Meta`).textContent = `Владелец: ${issued.actor_id} · назначение: ${purpose === 'encryption' ? 'шифрование' : 'подпись'} · версия: ${issued.key_version} · номер: ${item.serial_number} · срок: ${new Date(item.valid_from).toLocaleDateString('ru-RU')} — ${new Date(item.valid_until).toLocaleDateString('ru-RU')} · CA SHA-256: ${item.ca_fingerprint_sha256}`;
  }
}

function showRoot(root) {
  field('rootCertificate').value = root.certificate_pem;
  field('rootFingerprint').textContent = `Отпечаток этого корня · SHA-256: ${root.fingerprint_sha256} · действует до ${new Date(root.valid_until).toLocaleDateString('ru-RU')}`;
}

function unlockChallenge() {
  field('challengeSection').classList.remove('locked');
  field('issueChallenge').disabled = false;
}

function updateExampleProgress() {
  field('exampleProgress').textContent = `Общий пример: ${exampleSolved ? 'расшифрован' : 'ожидается'} · другой ключ: ${wrongKeyObserved ? 'отказ наблюдался в браузере' : 'ожидается'}`;
  if (exampleSolved && wrongKeyObserved) {
    unlockChallenge();
    result('challengeResult', 'Оба опыта выполнены в браузере. Получите одноразовое задание от сервера.');
  }
}

function invalidateAnswer() {
  inputVersion += 1;
  answerInput.value = '';
  field('verifyAnswer').disabled = true;
  if (challengeId) result('challengeResult', 'Ключ или исходный текст изменён. Расшифруйте задание заново.');
}

keyInput.addEventListener('input', invalidateAnswer);
cipherInput.addEventListener('input', invalidateAnswer);

async function loadExample(name, target) {
  const response = await fetch(`/examples/${name}`);
  if (!response.ok) throw new Error('Не удалось загрузить пример.');
  target.value = (await response.text()).trim();
  invalidateAnswer();
}

field('loadKey').addEventListener('click', async () => {
  try { await loadExample('training-key.pem', keyInput); result('exampleResult', 'Учебный ключ вставлен.'); }
  catch (error) { result('exampleResult', error.message, 'error'); }
});

field('loadWrongKey').addEventListener('click', async () => {
  try { await loadExample('wrong-key.pem', keyInput); result('exampleResult', 'Другой ключ вставлен. Попробуйте расшифровать тот же текст.'); }
  catch (error) { result('exampleResult', error.message, 'error'); }
});

field('loadCipher').addEventListener('click', async () => {
  try { await loadExample('ciphertext.txt', cipherInput); result('exampleResult', 'Шифротекст вставлен.'); }
  catch (error) { result('exampleResult', error.message, 'error'); }
});

field('decryptExample').addEventListener('click', async () => {
  try {
    const plaintext = await decryptRsaOaepText(keyInput.value, cipherInput.value);
    result('exampleResult', `Расшифровано: ${plaintext}`, 'success');
    const [trainingKey, , publishedCiphertext] = await examples;
    if (keyInput.value.trim() === trainingKey && cipherInput.value.trim() === publishedCiphertext) {
      exampleSolved = true;
      updateExampleProgress();
    }
  } catch (error) {
    invalidateAnswer();
    const message = error.name === 'OperationError'
      ? 'Расшифрование не удалось: ключ не подходит или шифротекст изменён.'
      : error.message;
    result('exampleResult', message, 'error');
    if (error.name === 'OperationError') {
      try {
        const [, wrongKey, publishedCiphertext] = await examples;
        if (keyInput.value.trim() === wrongKey && cipherInput.value.trim() === publishedCiphertext) {
          wrongKeyObserved = true;
          updateExampleProgress();
        }
      } catch { /* The visible error above already reports the failed request. */ }
    }
  }
});

field('issueChallenge').addEventListener('click', async () => {
  try {
    const challenge = await api('/api/challenges', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    challengeId = challenge.challenge_id;
    challengeCipher.value = challenge.ciphertext;
    answerInput.value = '';
    field('decryptChallenge').disabled = false;
    field('verifyAnswer').disabled = true;
    field('expiry').textContent = `Действует до ${new Date(challenge.expires_at).toLocaleTimeString('ru-RU')}`;
    result('challengeResult', 'Задание получено. Расшифруйте его учебным ключом.');
  } catch (error) { result('challengeResult', error.message, 'error'); }
});

field('decryptChallenge').addEventListener('click', async () => {
  const version = inputVersion;
  try {
    const answer = await decryptRsaOaepText(keyInput.value, challengeCipher.value);
    if (version !== inputVersion) return;
    answerInput.value = answer;
    field('verifyAnswer').disabled = false;
    result('challengeResult', 'Текст получен в браузере. Отправьте его на проверку.');
  } catch (error) {
    answerInput.value = '';
    field('verifyAnswer').disabled = true;
    const message = error.name === 'OperationError'
      ? 'Расшифрование не удалось: ключ не подходит или шифротекст изменён.'
      : error.message;
    result('challengeResult', message, 'error');
  }
});

field('verifyAnswer').addEventListener('click', async () => {
  if (!challengeId) return;
  try {
    const verification = await api(`/api/challenges/${encodeURIComponent(challengeId)}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answer: answerInput.value }),
    });
    if (verification.verified) {
      await refreshState();
      result('challengeResult', 'Ответ верный. Подготовительный шаг подтверждён сервером.', 'success');
    } else {
      result('challengeResult', 'Ответ не совпал. Проверьте ключ и шифротекст.', 'error');
    }
  } catch (error) { result('challengeResult', error.message, 'error'); }
});

field('generateKeys').addEventListener('click', async () => {
  field('generateKeys').disabled = true;
  result('keysResult', 'Создаются две пары RSA. Подождите несколько секунд.');
  try {
    const created = await generatePersonalKeys();
    await saveKeys(actorId, created);
    personalKeys = created;
    keyChallenge = null;
    field('personalCipher').value = '';
    field('signingText').value = '';
    field('personalAnswer').value = '';
    field('signatureOutput').value = '';
    field('keyFingerprints').textContent = '';
    field('requestKeyProof').disabled = false;
    field('proveKeys').disabled = true;
    field('confirmKeys').disabled = true;
    result('keysResult', 'Две разные пары созданы. Закрытые ключи сохранены в IndexedDB этого браузера.', 'success');
  } catch (error) {
    try {
      const existing = await loadKeys(actorId);
      if (existing) {
        personalKeys = existing;
        field('requestKeyProof').disabled = false;
        result('keysResult', 'В другой вкладке уже созданы ключи для этой записи. Загружена сохранённая пара.');
      } else {
        result('keysResult', `Ключи не удалось сохранить: ${error.message}`, 'error');
      }
    } catch {
      result('keysResult', `Ключи не удалось сохранить: ${error.message}`, 'error');
    }
  } finally {
    if (!keysVerified && !personalKeys) field('generateKeys').disabled = false;
  }
});

field('requestKeyProof').addEventListener('click', async () => {
  if (!personalKeys) return;
  try {
    const challenge = await api('/api/key-proofs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryption_spki: personalKeys.encryptionSpki,
        signing_spki: personalKeys.signingSpki,
      }),
    });
    keyChallenge = challenge;
    field('personalCipher').value = challenge.ciphertext;
    field('signingText').value = challenge.signing_text;
    field('personalAnswer').value = '';
    field('signatureOutput').value = '';
    field('proveKeys').disabled = false;
    field('confirmKeys').disabled = true;
    field('keyExpiry').textContent = `Действует до ${new Date(challenge.expires_at).toLocaleTimeString('ru-RU')}`;
    field('keyFingerprints').textContent = `SHA-256 открытых ключей · шифрование: ${challenge.encryption_fingerprint} · подпись: ${challenge.signing_fingerprint}`;
    result('keysResult', 'Сервер выдал два задания. Расшифруйте секрет и подпишите текст в браузере.');
  } catch (error) { result('keysResult', error.message, 'error'); }
});

field('proveKeys').addEventListener('click', async () => {
  if (!personalKeys || !keyChallenge) return;
  try {
    const proof = await provePersonalKeys(personalKeys, keyChallenge);
    field('personalAnswer').value = proof.answer;
    field('signatureOutput').value = proof.signature;
    field('confirmKeys').disabled = false;
    result('keysResult', 'Ответ и подпись получены в браузере. Отправьте их на серверную проверку.');
  } catch (error) {
    field('personalAnswer').value = '';
    field('signatureOutput').value = '';
    field('confirmKeys').disabled = true;
    result('keysResult', `Проверка закрытых ключей в браузере не удалась: ${error.message}`, 'error');
  }
});

field('confirmKeys').addEventListener('click', async () => {
  if (!keyChallenge) return;
  try {
    const proof = await api(`/api/key-proofs/${encodeURIComponent(keyChallenge.challenge_id)}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answer: field('personalAnswer').value, signature: field('signatureOutput').value }),
    });
    if (proof.verified) {
      await refreshState();
      result('keysResult', 'Сервер проверил расшифрование и подпись. Шаг «Личные ключи» подтверждён.', 'success');
    } else {
      const failed = [!proof.encryption_verified && 'расшифрование', !proof.signature_verified && 'подпись'].filter(Boolean).join(' и ');
      result('keysResult', `Проверка не пройдена: ${failed}. Исправьте результат или получите новые задания.`, 'error');
    }
  } catch (error) { result('keysResult', error.message, 'error'); }
});

field('showRoot').addEventListener('click', async () => {
  try {
    const root = await api('/api/ca');
    showRoot(root);
    result('certificatesResult', certificatesIssued
      ? 'Корень показан. Сравните его отпечаток с контрольным значением от преподавателя.'
      : 'Корень показан. После подтверждения личных ключей получите сертификаты.');
  } catch (error) { result('certificatesResult', error.message, 'error'); }
});

field('issueCertificates').addEventListener('click', async () => {
  try {
    const issued = await api('/api/certificates', { method: 'POST' });
    certificatesIssued = true;
    certificatesCurrent = true;
    certificatesReady = false;
    showCertificates(issued);
    field('issueCertificates').disabled = true;
    field('verifyCertificates').disabled = false;
    result('certificatesResult', 'Два сертификата выданы. Сверьте отпечаток корня и подтвердите проверку.');
  } catch (error) { result('certificatesResult', error.message, 'error'); }
});

field('verifyCertificates').addEventListener('click', async () => {
  try {
    const check = await api('/api/certificates/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ca_fingerprint_sha256: field('teacherFingerprint').value }),
    });
    if (check.verified) {
      await refreshState();
      result('certificatesResult', 'Сервер проверил подписи CA, назначение и владельца обоих сертификатов. Контрольный отпечаток совпал.', 'success');
    } else {
      result('certificatesResult', 'Контрольный отпечаток CA не совпал. Сверьте его с сообщённым преподавателем значением.', 'error');
    }
  } catch (error) { result('certificatesResult', error.message, 'error'); }
});

field('issueSignatureChallenge').addEventListener('click', async () => {
  try {
    const challenge = await api('/api/signature-challenges', { method: 'POST' });
    signatureChallenge = challenge;
    ownExerciseSignature = null;
    temporaryExercise = null;
    changedExerciseChecked = false;
    field('signatureChallengeText').value = challenge.text;
    field('signatureCertificateSerial').textContent = `Сертификат подписи · серийный номер: ${challenge.certificate_serial_number}`;
    field('signatureExpiry').textContent = `Действует до ${new Date(challenge.expires_at).toLocaleTimeString('ru-RU')}`;
    for (const id of ['ownExerciseSignature', 'temporaryExerciseSpki', 'temporaryExerciseSignature', 'alteredExerciseText']) field(id).value = '';
    field('signPersonalChallenge').disabled = false;
    field('signTemporaryChallenge').disabled = false;
    field('suggestChangedText').disabled = false;
    field('checkChangedText').disabled = true;
    updateSignatureSubmit();
    result('ownSignatureResult', 'Подпишите исходный текст своим ключом.');
    result('temporarySignatureResult', 'Создайте временную пару и подпишите тот же текст.');
    result('changedSignatureResult', 'Измените один символ после получения личной подписи.');
    result('signatureResult', 'Текст выдан сервером. Пройдите три опыта по порядку.');
  } catch (error) { result('signatureResult', error.message, 'error'); }
});

field('signPersonalChallenge').addEventListener('click', async () => {
  if (!signatureChallenge || !personalKeys) return;
  try {
    const proof = await signPersonalText(personalKeys, signatureChallenge.text);
    ownExerciseSignature = proof.validForCertificateKey ? proof.signature : null;
    changedExerciseChecked = false;
    field('ownExerciseSignature').value = proof.signature;
    field('checkChangedText').disabled = !ownExerciseSignature;
    updateSignatureSubmit();
    result('changedSignatureResult', 'Личная подпись обновлена. Проверьте изменённый текст ещё раз.');
    result('ownSignatureResult', proof.validForCertificateKey
      ? 'Подпись верна для личного открытого ключа. Сервер проверит её по сертификату.'
      : 'Подпись не прошла локальную проверку личным открытым ключом.',
    proof.validForCertificateKey ? 'success' : 'error');
  } catch (error) { result('ownSignatureResult', error.message, 'error'); }
});

field('signTemporaryChallenge').addEventListener('click', async () => {
  if (!signatureChallenge || !personalKeys) return;
  try {
    const proof = await signTemporaryText(personalKeys, signatureChallenge.text);
    temporaryExercise = proof.validForTemporaryKey && !proof.validForCertificateKey ? proof : null;
    field('temporaryExerciseSpki').value = proof.spki;
    field('temporaryExerciseSignature').value = proof.signature;
    updateSignatureSubmit();
    result('temporarySignatureResult', temporaryExercise
      ? 'Временная подпись верна для временного ключа; ключ из вашего сертификата её отклоняет.'
      : 'Проверка временной подписи дала неожиданный результат.',
    temporaryExercise ? 'success' : 'error');
  } catch (error) { result('temporarySignatureResult', error.message, 'error'); }
});

field('suggestChangedText').addEventListener('click', () => {
  if (!signatureChallenge) return;
  field('alteredExerciseText').value = changeOneCharacter(signatureChallenge.text);
  changedExerciseChecked = false;
  updateSignatureSubmit();
  result('changedSignatureResult', 'Один символ изменён. Проверьте прежнюю подпись.');
});

field('alteredExerciseText').addEventListener('input', () => {
  changedExerciseChecked = false;
  updateSignatureSubmit();
  result('changedSignatureResult', 'Текст изменён. Повторите локальную проверку прежней подписи.');
});

field('checkChangedText').addEventListener('click', async () => {
  if (!signatureChallenge || !ownExerciseSignature || !personalKeys) return;
  try {
    const check = await checkAlteredText(
      personalKeys, signatureChallenge.text, field('alteredExerciseText').value,
      ownExerciseSignature,
    );
    changedExerciseChecked = check.originalValid && !check.alteredValid;
    updateSignatureSubmit();
    result('changedSignatureResult', changedExerciseChecked
      ? 'Для исходного текста подпись верна, после изменения символа — недействительна.'
      : 'Прежняя подпись дала неожиданный результат.',
    changedExerciseChecked ? 'success' : 'error');
  } catch (error) {
    changedExerciseChecked = false;
    updateSignatureSubmit();
    result('changedSignatureResult', error.message, 'error');
  }
});

field('verifySignatureExercise').addEventListener('click', async () => {
  if (!signatureChallenge || !ownExerciseSignature || !temporaryExercise || !changedExerciseChecked) return;
  try {
    const check = await api(`/api/signature-challenges/${encodeURIComponent(signatureChallenge.challenge_id)}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        own_signature: ownExerciseSignature,
        temporary_spki: temporaryExercise.spki,
        temporary_signature: temporaryExercise.signature,
        altered_text: field('alteredExerciseText').value,
      }),
    });
    if (check.verified) {
      await refreshState();
      result('signatureResult', 'Сервер подтвердил: своя подпись верна, временная подходит только временному ключу, изменённый текст нарушает подпись.', 'success');
    } else {
      result('signatureResult', `Сервер отклонил опыт. Личная подпись: ${check.own_valid ? 'верна' : 'нет'}; временная: ${check.temporary_valid ? 'верна для временного ключа' : 'неверна'}; отказ по сертификату: ${check.temporary_rejected_by_certificate ? 'есть' : 'нет'}; отказ после изменения: ${check.changed_text_rejected ? 'есть' : 'нет'}.`, 'error');
    }
  } catch (error) { result('signatureResult', error.message, 'error'); }
});

field('prepareOutbound').addEventListener('click', async () => {
  try {
    serviceCertificate = await api('/api/service-certificate');
    outboundChallenge = await api('/api/outbound-packages/challenges', { method: 'POST' });
    outboundPackage = null;
    field('serviceCertificate').value = serviceCertificate.certificate_pem;
    field('serviceCertificateMeta').textContent = `Участник: ${serviceCertificate.actor_id} · серийный номер: ${serviceCertificate.serial_number} · CA SHA-256: ${serviceCertificate.ca_fingerprint_sha256} · срок до ${new Date(serviceCertificate.valid_until).toLocaleString('ru-RU')} · пакет: ${outboundChallenge.package_id}`;
    field('outboundJson').value = '';
    field('encryptOutbound').disabled = false;
    field('sendOutbound').disabled = true;
    result('outboundResult', 'Сертификат и одноразовый ID получены. Введите учебный текст и зашифруйте его.');
  } catch (error) { result('outboundResult', error.message, 'error'); }
});

field('outboundText').addEventListener('input', () => {
  outboundPackage = null;
  field('outboundJson').value = '';
  field('sendOutbound').disabled = true;
});

field('encryptOutbound').addEventListener('click', async () => {
  if (!outboundChallenge || !serviceCertificate) return;
  const message = field('outboundText').value.trim();
  if (!message || message.length > 500) return result('outboundResult', 'Введите учебный текст длиной от 1 до 500 символов.', 'error');
  try {
    outboundPackage = await encryptPackage(message, outboundChallenge, serviceCertificate.encryption_spki);
    field('outboundJson').value = JSON.stringify(outboundPackage, null, 2);
    field('sendOutbound').disabled = false;
    result('outboundResult', 'Пакет готов. Сравните исходный текст и JSON, затем отправьте пакет серверу.');
  } catch (error) { result('outboundResult', error.message, 'error'); }
});

field('sendOutbound').addEventListener('click', async () => {
  if (!outboundPackage) return;
  try {
    const check = await api(`/api/outbound-packages/${encodeURIComponent(outboundPackage.package_id)}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package: outboundPackage }),
    });
    await refreshState();
    result('outboundResult', `Пакет проверен сервером. SHA-256 канонического JSON: ${check.package_hash_sha256}`, 'success');
    field('sendOutbound').disabled = true;
  } catch (error) { result('outboundResult', error.message, 'error'); }
});

field('requestInbound').addEventListener('click', async () => {
  try {
    const issued = await api('/api/inbound-packages', { method: 'POST' });
    inboundPackage = issued.package;
    field('inboundJson').value = JSON.stringify(inboundPackage, null, 2);
    field('inboundAnswer').value = '';
    field('decryptInbound').disabled = !personalKeys;
    field('verifyInbound').disabled = true;
    field('inboundExpiry').textContent = `Действует до ${new Date(issued.expires_at).toLocaleTimeString('ru-RU')}`;
    result('inboundResult', 'Пакет получен. Изучите JSON и расшифруйте его личным ключом.');
  } catch (error) { result('inboundResult', error.message, 'error'); }
});

field('decryptInbound').addEventListener('click', async () => {
  if (!inboundPackage || !personalKeys) return;
  try {
    if (inboundPackage.recipient_actor_id !== actorId ||
        inboundPackage.recipient_certificate_serial !== (await api('/api/certificates')).encryption.serial_number) {
      throw new Error('Пакет адресован другому участнику или сертификату.');
    }
    field('inboundAnswer').value = await decryptPackage(inboundPackage, personalKeys.encryptionPrivateKey);
    field('verifyInbound').disabled = false;
    result('inboundResult', 'Секрет расшифрован в браузере. Отправьте его на проверку.');
  } catch (error) { result('inboundResult', `Расшифрование не удалось: ${error.message}`, 'error'); }
});

field('verifyInbound').addEventListener('click', async () => {
  if (!inboundPackage) return;
  try {
    const check = await api(`/api/inbound-packages/${encodeURIComponent(inboundPackage.package_id)}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answer: field('inboundAnswer').value }),
    });
    if (!check.verified) return result('inboundResult', 'Ответ не совпал. Проверьте сертификат и закрытый ключ.', 'error');
    await refreshState();
    field('verifyInbound').disabled = true;
    result('inboundResult', 'Одноразовый секрет подтверждён сервером. Все технические шаги завершены.', 'success');
  } catch (error) { result('inboundResult', error.message, 'error'); }
});

field('submitLab').addEventListener('click', async () => {
  try {
    await api('/api/submissions', { method: 'POST' });
    await refreshState();
  } catch (error) { result('submissionResult', error.message, 'error'); }
});

for (const id of ['studentSurname', 'studentGivenName', 'studentGroup']) {
  field(id).addEventListener('input', () => {
    studentDirty = true;
    result('studentResult', 'Изменения ещё не сохранены.');
    field('submitLab').disabled = true;
  });
}

field('saveStudent').addEventListener('click', async () => {
  try {
    await api('/api/student', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ surname: field('studentSurname').value, given_name: field('studentGivenName').value, group: field('studentGroup').value }),
    });
    studentDirty = false;
    await refreshState();
  } catch (error) { result('studentResult', error.message, 'error'); }
});

try {
  const state = await refreshState();
  if (state.completed) {
    result('challengeResult', 'Этот шаг уже подтверждён. Можно повторить опыт.','success');
    field('exampleProgress').textContent = 'Локальные опыты можно повторить; подготовительный шаг уже подтверждён сервером.';
  }
} catch (error) {
  result('challengeResult', error.message, 'error');
}
