# CryptoLab Training Decryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the first CryptoLab exercise locally: decrypt a published example in the browser, then answer a one-time server challenge and see one confirmed progress step.

**Architecture:** FastAPI serves one HTML/JavaScript page and a small API. A deliberately public RSA-OAEP training key is imported into Web Crypto as PKCS#8; the server uses its public half to encrypt random challenges and keeps only answer hashes in memory. An HttpOnly local session cookie binds a challenge and progress to one browser profile.

**Tech Stack:** Python 3, FastAPI, Uvicorn, cryptography, pytest, browser Web Crypto API, plain HTML/CSS/JavaScript.

**Spec:** `/Users/rdm/Documents/РАНХИГС/02-practice/lab-06-cryptolab-spec.md` sections 6-8. This is a local first-stage prototype; no roster or permanent result storage yet.

## Global Constraints

- Listen on `127.0.0.1`; no external deployment.
- Keep CA and personal student keys out of this project.
- The training private key is intentionally public; only the one-time answer is secret until verified.
- The HTML prototype in the course repository stays unchanged.

## Review Focus

- A wrong key or damaged ciphertext must show an error without claiming progress.
- Another browser session must not redeem a challenge issued to the first.
- Expired challenges and repeated submissions must not create extra progress.
- Raw challenge answers must not be stored in the server's state or logs.
- A browser reload should retain this stage's progress while the local server stays running.

---

### Task 1: Local challenge API

**Files:** `app/main.py`, `examples/*`, `tests/test_api.py`, `pyproject.toml`.

**Interfaces:** `GET /api/state`, `POST /api/challenges`, `POST /api/challenges/{challenge_id}/verify`, `GET /examples/{name}`. JSON uses `ciphertext`, `challenge_id`, `expires_at`, `answer`, `verified`, and `completed`.

- [x] Write tests for session creation, public example, challenge success, wrong answer, expiry, replay, and cross-session rejection.
- [x] Run pytest and observe missing app/API failures.
- [x] Implement a minimal FastAPI app with an in-memory challenge store and session progress.
- [x] Run pytest until all Task 1 tests pass.

### Task 2: Browser workbench

**Files:** `web/index.html`, `web/app.js`, `web/styles.css`, `tests/test_web_crypto.mjs`, `README.md`.

**Interfaces:** The page imports pasted PKCS#8 PEM, decodes base64url ciphertext, decrypts with RSA-OAEP/SHA-256, shows plaintext, requests a challenge, and submits its answer. `GET /` serves the page.

- [x] Write a Node Web Crypto test for correct and wrong training keys; observe failure before the browser module exists.
- [x] Implement the workbench with explicit input, decryption, challenge, submit, and one-step progress states.
- [x] Run Python and Node tests, then inspect the page and complete the flow in a browser.
