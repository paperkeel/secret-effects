# Architecture

## Design goals

Secret Effects optimizes one operation. A client loads one complete environment.
It does not fetch individual values.

The control service never receives a credential master key. It never receives
plaintext bundle values. Repository tooling validates and encrypts values before
upload.

## Credential hierarchy

| Type        | Scope                   | Read values     | Create or revoke                   |
| ----------- | ----------------------- | --------------- | ---------------------------------- |
| Global      | service                 | no              | CI/CD, Project, Agent, Environment |
| CI/CD       | service                 | no              | Project, Agent, Environment        |
| Project     | one project             | project bundles | Environment                        |
| Agent       | service management      | no              | none                               |
| Environment | one project environment | one environment | none                               |

Bootstrap creates the only Global credential. The bootstrap endpoint becomes
unusable after that operation. The API does not permit Global credential
rotation or revocation.

Each credential has this form:

```text
secret_effects_v1_payload:<base58>_signature:<base58>_checksum:<32hex>_key:<128hex>
```

The final key contains 64 random bytes. HKDF derives separate Ed25519 and
X25519 keys. The signed payload includes the API origin and all scope data.
The checksum detects common copy errors before any network request.

## Write path

1. Repository code builds a Zod-backed schema manifest.
2. The Project client registers the manifest digest.
3. The client resolves environment mirrors.
4. The client validates the complete environment.
5. The client creates one random AES-256-GCM data key.
6. The client encrypts the complete environment once.
7. The client wraps that data key for each signed public recipient descriptor.
8. The client signs the envelope with its Project credential.
9. The API checks the signature, schema digest, scope, and base version.
10. The API adds an issuer-signed acceptance proof.
11. The project's Durable Object serializes the publication.
12. R2 stores the encrypted envelope.
13. The service purges the environment cache tag.

The API uses optimistic base versions and idempotency keys. These fields prevent
lost updates and duplicate publications.

## Read path

1. The client parses its one `SECRET_EFFECTS_KEY` value.
2. The client signs the full HTTP request.
3. D1 checks status, scope, expiration, and replay nonce.
4. The Worker reads the encrypted bundle from cache or R2.
5. The Worker returns the complete encrypted bundle.
6. The client verifies the issuer acceptance and Project author signatures.
7. The client unwraps the data key and decrypts the bundle.
8. Zod and `@t3-oss/env-core` validate the complete result.

Decrypted values exist only in client request memory. The service cache contains
the encrypted response body. Its lifetime is five minutes.

## Storage

| Service                | Stored data                                                             |
| ---------------------- | ----------------------------------------------------------------------- |
| D1                     | projects, environments, credential public keys, status, schemas, nonces |
| R2                     | versioned encrypted environment bundles                                 |
| Project Durable Object | current pointers, idempotency records, publication audit                |
| Audit Durable Object   | append-only control and publication hash chain                          |
| Cloudflare cache       | complete encrypted bundle for five minutes                              |
| Queue                  | cache purge retry messages                                              |

Default environments are `local`, `dev`, and `production`. The API has no delete
or rename operation for environments. It has no environment count limit.

## Cache changes

Each successful publication requests a global purge for one environment tag.
If that request fails, a Queue consumer retries it. An authorized operator can
also request the same purge with `secreteffects cache purge`.

The response to an authenticated client is private and not cacheable. The
Worker uses a separate internal cache key after authentication succeeds.
