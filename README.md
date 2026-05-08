# BlackPay

> **B2B Privacy-First Payment Gateway** with Post-Quantum Cryptography, Zero-Knowledge Proofs, and Multi-Currency Support.

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.x-green?logo=django)](https://djangoproject.com)
[![C++](https://img.shields.io/badge/C++-20-blue?logo=c%2B%2B)](https://isocpp.org)
[![liboqs](https://img.shields.io/badge/liboqs-0.15.0-purple)](https://github.com/open-quantum-safe/liboqs)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Overview

BlackPay is an enterprise-grade B2B payment gateway built with a privacy-first architecture. Every transaction is protected by Post-Quantum Cryptography (PQC) algorithms standardised by NIST (FIPS 203/204/205) and approved by BSI TR-02102-1, ensuring security against both classical and quantum adversaries.

The cryptographic engine is written in C++ using [liboqs](https://github.com/open-quantum-safe/liboqs) and exposed to Django via pybind11 bindings — keeping all security-critical operations outside Python's memory model.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    BlackPay Platform                     │
├─────────────────┬───────────────────┬───────────────────┤
│   Django 5.x    │   C++ Crypto      │   External        │
│   REST API      │   Engine          │   Services        │
│                 │                   │                   │
│ ┌─────────────┐ │ ┌───────────────┐ │ ┌───────────────┐ │
│ │   users     │ │ │  pqc_engine   │ │ │ NOWPayments   │ │
│ │   payments  │ │ │  hybrid_kem   │ │ │ Stripe        │ │
│ │   wallet    │◄──►  symmetric    │ │ │ Wise          │ │
│ │   compliance│ │ │  zk_engine    │ │ │ Transak       │ │
│ │   zk_layer  │ │ │  secure_mem   │ │ └───────────────┘ │
│ │   ipfs      │ │ └───────────────┘ │ ┌───────────────┐ │
│ └─────────────┘ │   pybind11 bridge │ │ IPFS          │ │
│                 │                   │ │ PostgreSQL     │ │
│ Celery Workers  │ OpenSSL 3.x       │ │ Redis         │ │
│ Redis Broker    │ liboqs 0.15.0     │ └───────────────┘ │
└─────────────────┴───────────────────┴───────────────────┘
```

---

## Features

### Post-Quantum Cryptography
- **Algorithm Agility** — per-tenant PQC algorithm selection
- **KEM**: ML-KEM-512/768/1024, FrodoKEM, BIKE, HQC, Classic-McEliece
- **Signatures**: ML-DSA-44/65/87, Falcon-512/1024, SLH-DSA (all variants), MAYO, CROSS, OV, SNOVA
- **Hybrid KEM**: X25519 + ML-KEM-1024 (BSI TR-02102-1 compliant)
- **Symmetric**: AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA512

### Security
- Field-level AES-256-GCM encryption on all PII database columns
- Secure memory zeroization after key use (C++ `OPENSSL_cleanse`)
- Constant-time operations throughout the C++ engine
- Django Axes brute-force protection on all auth endpoints
- JWT (HS256) with 15-minute access tokens + refresh rotation

### Authentication & MFA
- Email + password (first factor)
- **PQC-MFA**: ML-DSA-65 signature challenge/response
- **FIDO2/WebAuthn**: hardware security key support
- TOTP fallback

### Zero-Knowledge Proofs
- Schnorr identity proofs (prove knowledge of signing key)
- Sufficient-balance proofs (prove balance ≥ amount without revealing either)
- Pedersen commitments with blinding factors

### Payments
| Provider | Type | Features |
|---|---|---|
| NOWPayments | Crypto on-ramp | 300+ coins, IPN webhooks |
| Stripe | Card / SEPA | PaymentIntents, webhooks, refunds |
| Wise | Bank transfer | Multi-currency, quotes, SWIFT/SEPA |
| Transak | Crypto on/off-ramp | Hosted checkout, 100+ countries |

### Compliance
- **GDPR**: Right to erasure (Art. 17), data portability (Art. 20), consent management (Art. 7)
- **KYC/AML**: Document submission via IPFS, PEP/sanctions screening hooks
- **OJK/BI**: Indonesian financial regulation compliance layer
- Immutable audit trail with ML-DSA-65 signatures
- Data retention policies with auto-deletion

### Storage
- Encrypted IPFS document storage (KYC documents, GDPR exports)
- AES-256-GCM envelope encryption before upload
- Content-addressed retrieval with integrity verification

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12, C++20 |
| Framework | Django 5.x + Django REST Framework |
| Database | PostgreSQL 16 |
| Cache / Broker | Redis 7 |
| Task Queue | Celery 5 + Celery Beat |
| PQC Library | liboqs 0.15.0 |
| Crypto | OpenSSL 3.x |
| Python Bridge | pybind11 |
| Auth | JWT (simplejwt) + FIDO2 + Django Axes |
| Storage | IPFS (ipfshttpclient) |
| Containers | Docker + docker-compose |

---

## Project Structure

```
BlackPay/
├── apps/
│   ├── api/              # Health check, version, algorithm registry
│   ├── compliance/       # GDPR, KYC/AML, audit trail, consent
│   ├── crypto_bridge/    # Python wrapper around C++ pybind11 module
│   ├── ipfs_storage/     # Encrypted IPFS document storage
│   ├── payments/         # NOWPayments, Stripe, Wise, Transak
│   ├── users/            # Auth, PQC-MFA, FIDO2, PQC key management
│   ├── wallet/           # Multi-currency balances, internal transfers
│   └── zk_layer/         # ZK proof orchestration
├── blackpay/
│   ├── settings.py       # Django settings
│   ├── urls.py           # Root URL config
│   ├── celery.py         # Celery app
│   ├── pqc_config.py     # PQC algorithm registry + per-tenant config
│   └── wsgi.py
├── crypto_engine/        # C++ PQC engine
│   ├── include/          # Headers (pqc_engine, symmetric, hybrid_kem, zk_engine)
│   ├── src/              # Implementations
│   ├── bindings/         # pybind11 bindings
│   └── tests/            # C++ unit tests
├── Dockerfile
├── Dockerfile.crypto     # Multi-stage C++ build
├── docker-compose.yml
├── manage.py
└── requirements.txt
```

---

## Quick Start

### With Docker (recommended)

```bash
git clone https://github.com/arr1781945-creator/BlackPay.git
cd BlackPay

# Configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY, DB credentials, payment provider keys

# Build and start all services
docker-compose up --build

# Run migrations
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py createsuperuser
```

### Without Docker (Termux / local)

```bash
# Install system dependencies
pkg install python cmake clang openssl libpq

# Virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Build C++ crypto engine
cd crypto_engine && mkdir build && cd build
cmake .. -Dpybind11_DIR=$(python -c "import pybind11; print(pybind11.get_cmake_dir())")
make -j4
cp blackpay_crypto*.so ../../
cd ../..

# Configure
cp .env.example .env
nano .env

# Database + run
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

> **Without C++ engine**: set `BLACKPAY_CRYPTO_STUB=1` in `.env` to use the built-in stub for development/testing.

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/register/` | Register new user + generate PQC keypair |
| POST | `/api/v1/auth/login/` | First-factor auth (returns MFA session) |
| POST | `/api/v1/auth/mfa/pqc/verify/` | PQC-MFA signature verification + JWT |
| POST | `/api/v1/auth/fido2/register/begin/` | Begin FIDO2 credential registration |
| POST | `/api/v1/auth/fido2/auth/complete/` | Complete FIDO2 assertion + JWT |
| GET  | `/api/v1/auth/keys/` | List PQC key pairs |
| POST | `/api/v1/auth/keys/generate/` | Generate new PQC key pair |

### Payments
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/payments/crypto/create/` | Initiate crypto payment (NOWPayments/Transak) |
| POST | `/api/v1/payments/fiat/create/` | Initiate fiat payment (Stripe/Wise) |
| GET  | `/api/v1/payments/transactions/` | List transactions |
| POST | `/api/v1/payments/webhooks/stripe/` | Stripe webhook (public) |
| POST | `/api/v1/payments/webhooks/nowpayments/` | NOWPayments IPN (public) |

### Wallet
| Method | Endpoint | Description |
|---|---|---|
| GET  | `/api/v1/wallet/` | Wallet overview + total USD balance |
| GET  | `/api/v1/wallet/balances/` | Per-currency balances |
| POST | `/api/v1/wallet/transfer/` | Internal wallet transfer + ZK proof |
| GET  | `/api/v1/wallet/rates/` | Live exchange rates |

### Zero-Knowledge
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/zk/balance-proof/` | Generate sufficient-balance ZK proof |
| POST | `/api/v1/zk/balance-proof/verify/` | Verify ZK balance proof |
| POST | `/api/v1/zk/identity-proof/` | Generate Schnorr identity proof |

### Compliance
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/compliance/gdpr/request/` | Submit GDPR subject rights request |
| GET  | `/api/v1/compliance/gdpr/export/` | Download portable data export (Art. 20) |
| GET/POST | `/api/v1/compliance/consent/` | Manage consent per purpose |
| POST | `/api/v1/compliance/kyc/submit/` | Submit KYC documents (IPFS hashes) |

---

## PQC Algorithm Support

All algorithms from [liboqs 0.15.0](https://github.com/open-quantum-safe/liboqs):

| Algorithm | Type | NIST Level | BSI | FIPS |
|---|---|---|---|---|
| ML-KEM-1024 | KEM | 5 | ✅ | ✅ FIPS 203 |
| ML-KEM-768 | KEM | 3 | ✅ | ✅ FIPS 203 |
| ML-DSA-65 | Signature | 3 | ✅ | ✅ FIPS 204 |
| ML-DSA-87 | Signature | 5 | ✅ | ✅ FIPS 204 |
| Falcon-1024 | Signature | 5 | ❌ | ✅ FIPS 206 |
| FrodoKEM-1344-AES | KEM | 5 | ✅ | ❌ |
| X25519 + ML-KEM-1024 | Hybrid KEM | 5 | ✅ | — |

Default: **ML-KEM-1024** (KEM) + **ML-DSA-65** (signatures) + **Hybrid KEM**.

---

## Environment Variables

```env
DJANGO_SECRET_KEY=your-secret-key
DJANGO_DEBUG=False
DATABASE_URL=postgres://blackpay:blackpay@db:5432/blackpay
REDIS_URL=redis://redis:6379/0
FIELD_ENCRYPTION_KEY=64-hex-chars   # generate: python -c "import secrets; print(secrets.token_hex(32))"

# PQC
PQC_DEFAULT_KEM=ML-KEM-1024
PQC_DEFAULT_SIG=ML-DSA-65

# Payment providers
NOWPAYMENTS_API_KEY=...
STRIPE_SECRET_KEY=sk_...
WISE_API_TOKEN=...
TRANSAK_API_KEY=...
```

See `.env.example` for the full list.

---

## Security Notes

- **Never commit `.env`** — it is in `.gitignore`
- `FIELD_ENCRYPTION_KEY` should come from an HSM or secret manager in production
- The C++ engine uses `OPENSSL_cleanse` for all key zeroization
- All authentication endpoints are protected by Django Axes (5 failures = 1 hour lockout)
- JWT access tokens expire after 15 minutes by default

---

## Built by

[@arr1781945-creator](https://github.com/arr1781945-creator) — solo developer, built on Android via Termux.

---

## License

MIT
