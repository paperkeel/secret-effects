import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
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
	type SealedBundle,
	type SealedRecipient,
} from "@secret-effects/protocol";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AUTH_INFO = encoder.encode("secret-effects/v1/authentication");
const DECRYPT_INFO = encoder.encode("secret-effects/v1/decryption");
const WRAP_INFO = encoder.encode("secret-effects/v1/wrapping");
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

export interface BundlePlaintext {
	values: Record<string, string>;
}

export interface BundleRecipientInput {
	identifier: string;
	publicKey: Uint8Array;
}

export function randomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
		"",
	);
}

export function hexToBytes(value: string): Uint8Array {
	if (value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
		throw new Error("The value is not valid hexadecimal data.");
	}
	return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) =>
		Number.parseInt(byte, 16),
	);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

export function base64UrlToBytes(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "base64url"));
}

export function generateMasterKey(): Uint8Array {
	return randomBytes(MASTER_KEY_BYTES);
}

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

export async function decodeCredentialPayload(
	bytes: Uint8Array,
): Promise<CredentialPayload> {
	const codec = bytes[0];
	const body = bytes.slice(1);
	const raw =
		codec === 1 ? await decompress(body) : codec === 0 ? body : undefined;
	if (raw === undefined) {
		throw new Error("The credential payload uses an unknown codec.");
	}
	return Schema.decodeUnknownSync(CredentialPayload)(decode(raw));
}

export function signPayload(
	payload: Uint8Array,
	privateKey: Uint8Array,
): Uint8Array {
	return ed25519.sign(payload, privateKey);
}

export function verifyPayload(
	payload: Uint8Array,
	signature: Uint8Array,
	publicKey: Uint8Array,
): boolean {
	return ed25519.verify(signature, payload, publicKey);
}

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
		const wrappedKey = await aesEncrypt(wrappingKey, wrapNonce, dataKey);
		recipients.push({
			identifier: recipient.identifier,
			ephemeralPublicKey: bytesToBase64Url(ephemeralPublicKey),
			nonce: bytesToBase64Url(wrapNonce),
			wrappedKey: bytesToBase64Url(wrappedKey),
		});
	}
	const contentVersion = bytesToHex(sha256(plaintext));
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
	};
	const signature = signPayload(
		encoder.encode(canonicalJson(unsigned)),
		input.author.keys.authPrivateKey,
	);
	return { ...unsigned, signature: bytesToBase64Url(signature) };
}

export async function openBundle(
	bundle: SealedBundle,
	credential: ParsedCredential,
): Promise<Record<string, string>> {
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
	const dataKey = await aesDecrypt(
		wrappingKey,
		base64UrlToBytes(recipient.nonce),
		base64UrlToBytes(recipient.wrappedKey),
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
		Object.entries(parsed.values).map(([key, value]) => {
			if (typeof value !== "string") {
				throw new Error(`The decrypted value for ${key} is not a string.`);
			}
			return [key, value];
		}),
	);
}

export function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}

async function aesEncrypt(
	keyBytes: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
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
			{ name: "AES-GCM", iv: toArrayBuffer(nonce) },
			key,
			toArrayBuffer(plaintext),
		),
	);
}

async function aesDecrypt(
	keyBytes: Uint8Array,
	nonce: Uint8Array,
	ciphertext: Uint8Array,
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
			{ name: "AES-GCM", iv: toArrayBuffer(nonce) },
			key,
			toArrayBuffer(ciphertext),
		),
	);
}

async function compress(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([toArrayBuffer(bytes)])
		.stream()
		.pipeThrough(new CompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompress(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([toArrayBuffer(bytes)])
		.stream()
		.pipeThrough(new DecompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

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

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const output = new Uint8Array(bytes.byteLength);
	output.set(bytes);
	return output.buffer;
}
