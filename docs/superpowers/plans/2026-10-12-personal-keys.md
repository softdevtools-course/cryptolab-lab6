# Personal Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the local CryptoLab workbench with separate personal encryption and signing keys and server-verified proof of possession.

**Architecture:** A browser session receives a local demo `student:<id>` actor. Web Crypto generates nonextractable RSA-OAEP and RSA-PSS private keys, saves them in IndexedDB under that actor, and exports only SPKI public keys. FastAPI issues one-time encryption and signing challenges, checks both answers, and records the second of six technical steps in memory.

**Tech Stack:** Existing FastAPI, cryptography, pytest, browser Web Crypto, IndexedDB, HTML/CSS/JavaScript, Node tests.

**Spec:** `/Users/rdm/Documents/РАНХИГС/02-practice/lab-06-cryptolab-spec.md` sections 3, 4, 7, and 8. Local demo actor is an explicit prototype substitute for the future CSV roster.

## Global Constraints

- Keep HTTP bound to `127.0.0.1`; no public deployment or course-repo edit.
- Generate distinct RSA-OAEP 2048/SHA-256 and RSA-PSS 2048/SHA-256 key pairs.
- Private `CryptoKey` objects are nonextractable and remain in IndexedDB; server receives SPKI only.
- Both server challenges expire and are bound to the same local session; confirmed progress is idempotent.
- CA, certificates, roster, persistent DB, and reset access remain outside this increment.

## Review Focus

- Reject malformed, weak, or identical submitted public keys.
- A different session or an expired challenge cannot verify keys.
- One correct proof and one invalid proof do not complete the step.
- Browser reload can recover keys, while loss of site data is explained clearly.
- Two tabs cannot overwrite one another's stored private keys for the same actor.
- Six-step progress never claims that the whole laboratory is complete after two steps.

---

### Task 1: Server proof of possession

**Files:** Modify `app/main.py`, `tests/test_api.py`.

**Interfaces:** `GET /api/state` adds `actor_id`, `keys_verified`, `steps_done`, `steps_total=6`; `POST /api/key-proofs` accepts two base64url SPKI values and returns a challenge ID, RSA-OAEP ciphertext, signing text, expiry, and key fingerprints; `POST /api/key-proofs/{id}/verify` accepts answer and RSA-PSS signature.

- [x] Add tests for the six-step state, good dual proof, one invalid proof, wrong session, expiry, and malformed or identical public keys.
- [x] Run `pytest -q` and observe expected failures.
- [x] Implement local actor session state, strict key parsing, challenge issue and verification.
- [x] Run `pytest -q` until green.

### Task 2: Browser keys and workbench

**Files:** Create `web/personal-keys.js`, `web/key-store.js`; modify `web/index.html`, `web/app.js`, `web/styles.css`, `app/main.py`, `package.json`, `tests/test_web_crypto.mjs`, `README.md`.

**Interfaces:** `generatePersonalKeys(subtle)`, `provePersonalKeys(keys, challenge, subtle)` and `loadKeys(actorId)`/`saveKeys(actorId, keys)`; UI actions create, restore, and prove keys. `/personal-keys.js` and `/key-store.js` are served as JavaScript.

- [x] Add Node Web Crypto tests for two distinct nonextractable private keys and successful proofs.
- [x] Run `npm test` and observe missing-feature failure.
- [x] Implement Web Crypto and IndexedDB modules; add visible key and proof controls.
- [x] Run `npm test` and `pytest -q` until green.
- [x] In the browser, prove both keys, reload, confirm IndexedDB restoration, and inspect the two-of-six progress bar.
- [x] Run final syntax, diff, and HTTP checks.
