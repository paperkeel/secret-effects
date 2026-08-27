# Security model

## Protected assets

The main protected assets are environment values and credential private keys.
The service also protects project structure, credential status, and audit data.

## Cryptography

- Credentials contain 64 random master-key bytes.
- HKDF-SHA-512 separates authentication and decryption key material.
- Ed25519 signs credentials, requests, and bundle envelopes.
- X25519 derives recipient-specific wrapping keys.
- HKDF-SHA-256 derives each AES wrapping key.
- AES-256-GCM encrypts values and wraps each data key.
- SHA-256 creates content, envelope, schema, and audit digests.

The service holds an issuer signing key. This key signs credential descriptors.
It cannot derive any credential master key. It cannot decrypt an uploaded
environment bundle.

## Request protection

Every authenticated request signs its method, path, query, timestamp, nonce,
and body digest. The API accepts a five-minute clock window. D1 rejects a reused
credential and nonce pair.

Credential revocation takes effect on the next authenticated request. Cached
bundles remain behind authentication. Cache entries cannot bypass a status check.

## Audit properties

One Durable Object serializes the control audit log. Each record contains the
previous record hash. The service exposes no audit mutation or deletion method.
Project publication history has a second per-project hash chain.

This design detects modification through the service API. A Cloudflare account
administrator can still delete infrastructure or replace Worker code. External
audit anchoring is not part of this version.

## Trust boundaries

- Trust Cloudflare to execute the deployed Worker and preserve service storage.
- Trust repository publishers before plaintext encryption.
- Do not trust R2, cache, Queue, D1, or network transport with plaintext values.
- Treat every rendered Secret Effects credential as a secret.
- Treat the Global credential as the offline root of trust.

The Global credential should remain outside CI after initial setup. CI uses one
CI/CD credential. Each runtime receives one Environment credential.

## Known limits

- A compromised publisher can upload harmful but correctly signed values.
- A compromised Project credential can read all bundles for that project.
- Revocation does not erase old ciphertext from a former recipient.
- Cloudflare account control can cause denial of service or metadata rollback.
- The API does not yet anchor audit roots outside Cloudflare.

Report security issues privately to the repository maintainers. Do not include
credentials, decrypted values, or private keys in an issue.
