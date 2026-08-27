/**
 * Implements Secret Effects credential and bundle cryptography.
 *
 * @remarks
 * Responsibility: Owns key derivation, credential encoding, request signatures, envelope encryption, and bundle verification.
 *
 * Boundary: Accepts protocol data and key material in memory. It does not persist credentials, keys, or decrypted values.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import bs58 from "bs58";
import { decode, encode } from "cbor-x";
import * as Schema from "effect/Schema";
import {
	CHECKSUM_HEX_LENGTH,
	CREDENTIAL_PREFIX,
	CredentialPayload,
	MASTER_KEY_BYTES,
	MASTER_KEY_HEX_LENGTH,
	canonicalJson,
	type CredentialIssueResponse,
	type SealedBundle,
	type SealedRecipient,
} from "@secret-effects/protocol";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AUTH_INFO = encoder.encode("secret-effects/v1/authentication");
const DECRYPT_INFO = encoder.encode("secret-effects/v1/decryption");
const WRAP_INFO = encoder.encode("secret-effects/v1/wrapping");
const MAX_CREDENTIAL_PAYLOAD_BYTES = 16 * 1024;
const CREDENTIAL_PATTERN = new RegExp(
	`^${CREDENTIAL_PREFIX}_payload:([1-9A-HJ-NP-Za-km-z]+)_signature:([1-9A-HJ-NP-Za-km-z]+)_checksum:([0-9a-f]{${CHECKSUM_HEX_LENGTH}})_key:([0-9a-f]{${MASTER_KEY_HEX_LENGTH}})$`,
);

export interface DerivedKeys {
	authPrivateKey: Uint8Array;
	authPublicKey: Uint8Array;
	decryptPrivateKey: Uint8Array;
	decryptPublicKey: Uint8Array;
}

export interface ParsedCredential {
	payload: CredentialPayload;
	payloadBytes: Uint8Array;
	signature: Uint8Array;
	masterKey: Uint8Array;
	keys: DerivedKeys;
	rendered: string;
}

export interface PublicCredential {
	payload: CredentialPayload;
	payloadBytes: Uint8Array;
	signature: Uint8Array;
}

export interface BundlePlaintext {
	values: Record<string, string>;
}

export interface BundleRecipientInput {
	identifier: string;
	publicKey: Uint8Array;
}

/**
 * Generates the requested number of cryptographically random bytes.
 *
 * @param length - The number of random bytes to generate.
 * @returns The generated random bytes.
 */
export function randomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return bytes;
}

/**
 * Encodes bytes as lowercase hexadecimal text.
 *
 * @param bytes - The byte sequence to process.
 * @returns The lowercase hexadecimal representation.
 */
export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
		"",
	);
}

/**
 * Decodes validated hexadecimal text into bytes.
 *
 * @param value - The hexadecimal text to decode.
 * @returns The decoded bytes.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export function hexToBytes(value: string): Uint8Array {
	if (value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
		throw new Error("The value is not valid hexadecimal data.");
	}
	return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) =>
		Number.parseInt(byte, 16),
	);
}

/**
 * Encodes bytes as base64url text.
 *
 * @param bytes - The byte sequence to process.
 * @returns The base64url representation.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

/**
 * Decodes base64url text into bytes.
 *
 * @param value - The base64url text to decode.
 * @returns The decoded bytes.
 */
export function base64UrlToBytes(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "base64url"));
}

/**
 * Generates a random Secret Effects master key.
 *
 * @returns A new random master key.
 */
export function generateMasterKey(): Uint8Array {
	return randomBytes(MASTER_KEY_BYTES);
}

/**
 * Derives authentication and decryption key pairs from one master key.
 *
 * @param masterKey - The secret master key used for deterministic key derivation.
 * @returns The deterministic authentication and decryption key pairs.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export function deriveKeys(masterKey: Uint8Array): DerivedKeys {
	if (masterKey.byteLength !== MASTER_KEY_BYTES) {
		throw new Error(`The master key must contain ${MASTER_KEY_BYTES} bytes.`);
	}
	const authPrivateKey = hkdf(sha512, masterKey, undefined, AUTH_INFO, 32);
	const decryptPrivateKey = hkdf(
		sha512,
		masterKey,
		undefined,
		DECRYPT_INFO,
		32,
	);
	return {
		authPrivateKey,
		authPublicKey: ed25519.getPublicKey(authPrivateKey),
		decryptPrivateKey,
		decryptPublicKey: x25519.getPublicKey(decryptPrivateKey),
	};
}

/**
 * Encodes and conditionally compresses a credential payload.
 *
 * @param payload - The credential or message bytes to sign or verify.
 * @returns The codec marker and encoded payload bytes.
 */
export async function encodeCredentialPayload(
	payload: CredentialPayload,
): Promise<Uint8Array> {
	const raw = new Uint8Array(encode(payload));
	const compressed = await compress(raw);
	if (compressed.byteLength + 1 < raw.byteLength + 1) {
		return concatBytes(new Uint8Array([1]), compressed);
	}
	return concatBytes(new Uint8Array([0]), raw);
}

/**
 * Decodes and validates a bounded credential payload.
 *
 * @param bytes - The byte sequence to process.
 * @returns The validated credential payload.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export async function decodeCredentialPayload(
	bytes: Uint8Array,
): Promise<CredentialPayload> {
	if (bytes.byteLength > MAX_CREDENTIAL_PAYLOAD_BYTES + 1) {
		throw new Error("The credential payload is too large.");
	}
	const codec = bytes[0];
	const body = bytes.slice(1);
	const raw =
		codec === 1
			? await decompress(body, MAX_CREDENTIAL_PAYLOAD_BYTES)
			: codec === 0
				? body
				: undefined;
	if (raw === undefined) {
		throw new Error("The credential payload uses an unknown codec.");
	}
	return Schema.decodeUnknownSync(CredentialPayload)(decode(raw));
}

/**
 * Signs payload bytes with an Ed25519 private key.
 *
 * @param payload - The credential or message bytes to sign or verify.
 * @param privateKey - The Ed25519 private key that creates the signature.
 * @returns The Ed25519 signature bytes.
 */
export function signPayload(
	payload: Uint8Array,
	privateKey: Uint8Array,
): Uint8Array {
	return ed25519.sign(payload, privateKey);
}

/**
 * Verifies an Ed25519 signature over payload bytes.
 *
 * @param payload - The credential or message bytes to sign or verify.
 * @param signature - The Ed25519 signature bytes to verify or encode.
 * @param publicKey - The Ed25519 public key that verifies the signature.
 * @returns True when the signature is valid.
 */
export function verifyPayload(
	payload: Uint8Array,
	signature: Uint8Array,
	publicKey: Uint8Array,
): boolean {
	return ed25519.verify(signature, payload, publicKey);
}

/**
 * Assembles signed payload bytes and a master key into one checked credential string.
 *
 * @param payloadBytes - The encoded credential payload bytes.
 * @param signature - The Ed25519 signature bytes to verify or encode.
 * @param masterKey - The secret master key used for deterministic key derivation.
 * @returns The complete checked credential string.
 */
export function assembleCredential(
	payloadBytes: Uint8Array,
	signature: Uint8Array,
	masterKey: Uint8Array,
): string {
	const payload = bs58.encode(payloadBytes);
	const signed = bs58.encode(signature);
	const key = bytesToHex(masterKey);
	const withoutChecksum = `${CREDENTIAL_PREFIX}_payload:${payload}_signature:${signed}_key:${key}`;
	const checksum = bytesToHex(sha256(encoder.encode(withoutChecksum))).slice(
		0,
		CHECKSUM_HEX_LENGTH,
	);
	return `${CREDENTIAL_PREFIX}_payload:${payload}_signature:${signed}_checksum:${checksum}_key:${key}`;
}

/**
 * Parses and verifies one active Secret Effects credential.
 *
 * @param rendered - The complete rendered credential string.
 * @returns The verified active credential and derived keys.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export async function parseCredential(
	rendered: string,
): Promise<ParsedCredential> {
	const match = CREDENTIAL_PATTERN.exec(rendered);
	if (match === null) {
		throw new Error("The Secret Effects credential has an invalid shape.");
	}
	const [, payloadText, signatureText, checksum, keyText] = match;
	if (
		payloadText === undefined ||
		signatureText === undefined ||
		checksum === undefined ||
		keyText === undefined
	) {
		throw new Error("The Secret Effects credential is incomplete.");
	}
	const withoutChecksum = `${CREDENTIAL_PREFIX}_payload:${payloadText}_signature:${signatureText}_key:${keyText}`;
	const expectedChecksum = bytesToHex(
		sha256(encoder.encode(withoutChecksum)),
	).slice(0, CHECKSUM_HEX_LENGTH);
	if (checksum !== expectedChecksum) {
		throw new Error("The Secret Effects credential checksum is invalid.");
	}
	const payloadBytes = bs58.decode(payloadText);
	const signature = bs58.decode(signatureText);
	const masterKey = hexToBytes(keyText);
	const payload = await decodeCredentialPayload(payloadBytes);
	const issuerPublicKey = hexToBytes(payload.issuerPublicKey);
	if (!verifyPayload(payloadBytes, signature, issuerPublicKey)) {
		throw new Error("The Secret Effects credential signature is invalid.");
	}
	const keys = deriveKeys(masterKey);
	if (
		bytesToHex(keys.authPublicKey) !== payload.authPublicKey ||
		(payload.decryptPublicKey !== null &&
			bytesToHex(keys.decryptPublicKey) !== payload.decryptPublicKey)
	) {
		throw new Error(
			"The Secret Effects credential key does not match its signed payload.",
		);
	}
	const now = Date.now();
	if (
		now < payload.notBefore ||
		(payload.expiresAt !== null && now >= payload.expiresAt)
	) {
		throw new Error("The Secret Effects credential is not active.");
	}
	return { payload, payloadBytes, signature, masterKey, keys, rendered };
}

/**
 * Exports the signed public portion of a parsed credential.
 *
 * @param credential - The credential that authenticates or decrypts the operation.
 * @returns The transferable signed public descriptor.
 */
export function exportPublicCredential(
	credential: ParsedCredential,
): CredentialIssueResponse {
	return {
		payload: bytesToBase64Url(credential.payloadBytes),
		signature: bytesToBase64Url(credential.signature),
	};
}

/**
 * Parses and verifies one active public credential descriptor.
 *
 * @param descriptor - The signed public credential fields to verify.
 * @returns The verified active public credential.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export async function parsePublicCredential(
	descriptor: CredentialIssueResponse,
): Promise<PublicCredential> {
	const payloadBytes = base64UrlToBytes(descriptor.payload);
	const signature = base64UrlToBytes(descriptor.signature);
	const payload = await decodeCredentialPayload(payloadBytes);
	if (
		!verifyPayload(payloadBytes, signature, hexToBytes(payload.issuerPublicKey))
	) {
		throw new Error("The public credential signature is invalid.");
	}
	const now = Date.now();
	if (
		now < payload.notBefore ||
		(payload.expiresAt !== null && now >= payload.expiresAt)
	) {
		throw new Error("The public credential is not active.");
	}
	return { payload, payloadBytes, signature };
}

/**
 * Creates authentication headers for one signed request.
 *
 * @param credential - The credential that authenticates or decrypts the operation.
 * @param method - The HTTP method that the signature authenticates.
 * @param path - The request path or local file path for the operation.
 * @param body - The exact request body bytes covered by the signature.
 * @param now - The request timestamp in Unix milliseconds.
 * @returns The request authentication headers.
 */
export async function signRequest(
	credential: ParsedCredential,
	method: string,
	path: string,
	body: Uint8Array,
	now = Date.now(),
): Promise<Headers> {
	const nonce = bytesToHex(randomBytes(16));
	const bodyDigest = bytesToHex(sha256(body));
	const message = encoder.encode(
		[method.toUpperCase(), path, String(now), nonce, bodyDigest].join("\n"),
	);
	const signature = signPayload(message, credential.keys.authPrivateKey);
	return new Headers({
		"x-secret-effects-id": credential.payload.identifier,
		"x-secret-effects-time": String(now),
		"x-secret-effects-nonce": nonce,
		"x-secret-effects-signature": bytesToBase64Url(signature),
	});
}

/**
 * Builds the canonical request authentication message.
 *
 * @param method - The HTTP method that the signature authenticates.
 * @param path - The request path or local file path for the operation.
 * @param timestamp - The signed request timestamp text.
 * @param nonce - The unique AES-GCM or request nonce.
 * @param body - The exact request body bytes covered by the signature.
 * @returns The canonical message bytes.
 */
export async function requestSigningMessage(
	method: string,
	path: string,
	timestamp: string,
	nonce: string,
	body: Uint8Array,
): Promise<Uint8Array> {
	const bodyDigest = bytesToHex(sha256(body));
	return encoder.encode(
		[method.toUpperCase(), path, timestamp, nonce, bodyDigest].join("\n"),
	);
}

/**
 * Encrypts and signs one environment bundle for its recipients.
 *
 * @param input - The validated operation data at this boundary.
 * @returns The signed encrypted bundle draft.
 */
export async function sealBundle(input: {
	project: string;
	environment: string;
	schemaDigest: string;
	values: Record<string, string>;
	recipients: readonly BundleRecipientInput[];
	author: ParsedCredential;
}): Promise<SealedBundle> {
	const dataKey = randomBytes(32);
	const nonce = randomBytes(12);
	const plaintext = encoder.encode(
		JSON.stringify({ values: input.values } satisfies BundlePlaintext),
	);
	const ciphertext = await aesEncrypt(dataKey, nonce, plaintext);
	const recipients: SealedRecipient[] = [];
	for (const recipient of input.recipients) {
		const ephemeralPrivateKey = randomBytes(32);
		const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
		const shared = x25519.getSharedSecret(
			ephemeralPrivateKey,
			recipient.publicKey,
		);
		const wrappingKey = hkdf(sha256, shared, undefined, WRAP_INFO, 32);
		const wrapNonce = randomBytes(12);
		const context = recipientContext(
			recipient.identifier,
			ephemeralPublicKey,
			recipient.publicKey,
		);
		const wrappedKey = await aesEncrypt(
			wrappingKey,
			wrapNonce,
			dataKey,
			context,
		);
		recipients.push({
			identifier: recipient.identifier,
			ephemeralPublicKey: bytesToBase64Url(ephemeralPublicKey),
			nonce: bytesToBase64Url(wrapNonce),
			wrappedKey: bytesToBase64Url(wrappedKey),
		});
	}
	const contentVersion = bytesToHex(hmac(sha256, dataKey, plaintext));
	const envelopeVersion = bytesToHex(
		sha256(encoder.encode(JSON.stringify(recipients))),
	);
	const unsigned = {
		format: "secret-effects-bundle-v1" as const,
		project: input.project,
		environment: input.environment,
		contentVersion,
		envelopeVersion,
		schemaDigest: input.schemaDigest,
		createdAt: Date.now(),
		nonce: bytesToBase64Url(nonce),
		ciphertext: bytesToBase64Url(ciphertext),
		recipients,
		author: input.author.payload.identifier,
		authorPublicKey: bytesToHex(input.author.keys.authPublicKey),
	};
	const signature = signPayload(
		encoder.encode(canonicalJson(unsigned)),
		input.author.keys.authPrivateKey,
	);
	return {
		...unsigned,
		signature: bytesToBase64Url(signature),
		serviceSignature: null,
	};
}

/**
 * Verifies and decrypts an accepted bundle for one recipient credential.
 *
 * @param bundle - The encrypted bundle or test draft for the operation.
 * @param credential - The credential that authenticates or decrypts the operation.
 * @returns The decrypted environment values.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
export async function openBundle(
	bundle: SealedBundle,
	credential: ParsedCredential,
): Promise<Record<string, string>> {
	if (bundle.serviceSignature === null) {
		throw new Error("The bundle has no service acceptance signature.");
	}
	const accepted = { ...bundle, serviceSignature: null };
	if (
		!verifyPayload(
			encoder.encode(canonicalJson(accepted)),
			base64UrlToBytes(bundle.serviceSignature),
			hexToBytes(credential.payload.issuerPublicKey),
		)
	) {
		throw new Error("The bundle service signature is invalid.");
	}
	const {
		signature,
		serviceSignature: _serviceSignature,
		...authorSigned
	} = bundle;
	if (
		!verifyPayload(
			encoder.encode(canonicalJson(authorSigned)),
			base64UrlToBytes(signature),
			hexToBytes(bundle.authorPublicKey),
		)
	) {
		throw new Error("The bundle author signature is invalid.");
	}
	const recipient = bundle.recipients.find(
		(candidate) => candidate.identifier === credential.payload.identifier,
	);
	if (recipient === undefined) {
		throw new Error(
			"The credential is not a recipient of this environment bundle.",
		);
	}
	const shared = x25519.getSharedSecret(
		credential.keys.decryptPrivateKey,
		base64UrlToBytes(recipient.ephemeralPublicKey),
	);
	const wrappingKey = hkdf(sha256, shared, undefined, WRAP_INFO, 32);
	const context = recipientContext(
		recipient.identifier,
		base64UrlToBytes(recipient.ephemeralPublicKey),
		credential.keys.decryptPublicKey,
	);
	const dataKey = await aesDecrypt(
		wrappingKey,
		base64UrlToBytes(recipient.nonce),
		base64UrlToBytes(recipient.wrappedKey),
		context,
	);
	const plaintext = await aesDecrypt(
		dataKey,
		base64UrlToBytes(bundle.nonce),
		base64UrlToBytes(bundle.ciphertext),
	);
	const parsed: unknown = JSON.parse(decoder.decode(plaintext));
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!("values" in parsed) ||
		typeof parsed.values !== "object" ||
		parsed.values === null
	) {
		throw new Error("The decrypted environment bundle has an invalid shape.");
	}
	return Object.fromEntries(
		Object.entries(parsed.values).map(
			/**
			 * Validates and returns one decrypted secret entry.
			 *
			 * @param entry - The decrypted secret name and value pair.
			 * @returns The validated key and string value entry.
			 * @throws {@link Error} When credential, key, or bundle data fails validation.
			 */
			([key, value]) => {
				if (typeof value !== "string") {
					throw new Error(`The decrypted value for ${key} is not a string.`);
				}
				return [key, value];
			},
		),
	);
}

/**
 * Encrypts plaintext with an AES-GCM key and nonce.
 *
 * @param keyBytes - The raw AES-GCM key bytes.
 * @param nonce - The unique AES-GCM or request nonce.
 * @param plaintext - The bytes to encrypt.
 * @param additionalData - The optional bytes that authentication binds without encryption.
 * @returns The authenticated ciphertext bytes.
 */
async function aesEncrypt(
	keyBytes: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
	additionalData?: Uint8Array,
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		toArrayBuffer(keyBytes),
		"AES-GCM",
		false,
		["encrypt"],
	);
	return new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: "AES-GCM",
				iv: toArrayBuffer(nonce),
				...(additionalData === undefined
					? {}
					: { additionalData: toArrayBuffer(additionalData) }),
			},
			key,
			toArrayBuffer(plaintext),
		),
	);
}

/**
 * Decrypts authenticated ciphertext with an AES-GCM key and nonce.
 *
 * @param keyBytes - The raw AES-GCM key bytes.
 * @param nonce - The unique AES-GCM or request nonce.
 * @param ciphertext - The authenticated ciphertext to decrypt.
 * @param additionalData - The optional bytes that authentication binds without encryption.
 * @returns The decrypted plaintext bytes.
 */
async function aesDecrypt(
	keyBytes: Uint8Array,
	nonce: Uint8Array,
	ciphertext: Uint8Array,
	additionalData?: Uint8Array,
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		toArrayBuffer(keyBytes),
		"AES-GCM",
		false,
		["decrypt"],
	);
	return new Uint8Array(
		await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: toArrayBuffer(nonce),
				...(additionalData === undefined
					? {}
					: { additionalData: toArrayBuffer(additionalData) }),
			},
			key,
			toArrayBuffer(ciphertext),
		),
	);
}

/**
 * Compresses bytes with the deflate format.
 *
 * @param bytes - The byte sequence to process.
 * @returns The compressed bytes.
 */
async function compress(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([toArrayBuffer(bytes)])
		.stream()
		.pipeThrough(new CompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Decompresses bounded deflate data into bytes.
 *
 * @param bytes - The byte sequence to process.
 * @param maximumBytes - The maximum permitted decompressed byte count.
 * @returns The decompressed bytes.
 * @throws {@link Error} When credential, key, or bundle data fails validation.
 */
async function decompress(
	bytes: Uint8Array,
	maximumBytes: number,
): Promise<Uint8Array> {
	const stream = new Blob([toArrayBuffer(bytes)])
		.stream()
		.pipeThrough(new DecompressionStream("deflate"));
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	while (true) {
		const result = await reader.read();
		if (result.done) {
			break;
		}
		total += result.value.byteLength;
		if (total > maximumBytes) {
			await reader.cancel();
			throw new Error("The decompressed credential payload is too large.");
		}
		chunks.push(result.value);
	}
	return concatBytes(...chunks);
}

/**
 * Concatenates byte arrays in input order.
 *
 * @param values - The byte arrays or environment values for the operation.
 * @returns One byte array with all input values.
 */
function concatBytes(...values: Uint8Array[]): Uint8Array {
	const total = values.reduce((sum, value) => sum + value.byteLength, 0);
	const output = new Uint8Array(total);
	let offset = 0;
	for (const value of values) {
		output.set(value, offset);
		offset += value.byteLength;
	}
	return output;
}

/**
 * Copies bytes into a standalone array buffer.
 *
 * @param bytes - The byte sequence to process.
 * @returns A standalone copy of the bytes.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const output = new Uint8Array(bytes.byteLength);
	output.set(bytes);
	return output.buffer;
}

/**
 * Builds the authenticated key-wrapping context for one recipient.
 *
 * @param identifier - The stable credential or recipient identifier.
 * @param ephemeralPublicKey - The ephemeral X25519 public key for this recipient.
 * @param recipientPublicKey - The recipient X25519 public key bound to the wrapping context.
 * @returns The encoded recipient context bytes.
 */
function recipientContext(
	identifier: string,
	ephemeralPublicKey: Uint8Array,
	recipientPublicKey: Uint8Array,
): Uint8Array {
	return encoder.encode(
		[
			"secret-effects/v1/recipient",
			identifier,
			bytesToHex(ephemeralPublicKey),
			bytesToHex(recipientPublicKey),
		].join("\n"),
	);
}
