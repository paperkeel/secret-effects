/**
 * Tests credential integrity and encrypted environment bundle boundaries.
 *
 * @remarks
 * Responsibility: Owns regression coverage for credential tampering, issuer pinning, recipient access, signatures, and wrapped-key context.
 *
 * Boundary: Uses deterministic issuer keys and generated test credentials. It does not persist secret material.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import bs58 from "bs58";
import { describe, expect, it } from "vitest";
import {
	canonicalJson,
	type CredentialPayload,
	type SealedBundle,
} from "@secret-effects/protocol";
import {
	assembleCredential,
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	deriveKeys,
	encodeCredentialPayload,
	exportPublicCredential,
	generateMasterKey,
	openBundle,
	parseCredential,
	parsePublicCredential,
	sealBundle,
	signPayload,
} from "./index.ts";

const TEST_ISSUER_PUBLIC_KEY = bytesToHex(
	ed25519.getPublicKey(new Uint8Array(32).fill(7)),
);

describe("Secret Effects credentials", credentialTests);
describe("encrypted environment bundles", bundleTests);

/**
 * Groups signed credential tests.
 */
function credentialTests() {
	it("round-trips Web API base64url data", roundTripsBase64Url);
	it("round-trips the signed self-contained credential", roundTripsCredential);
	it(
		"rejects a credential that changed after issuance",
		rejectsChangedCredential,
	);
	it(
		"rejects a changed signature after a valid checksum",
		rejectsChangedSignature,
	);
	it(
		"rejects a credential whose issuer key is not the pinned trust anchor",
		rejectsUnpinnedIssuer,
	);
	it(
		"rejects a public descriptor whose issuer key is not the pinned trust anchor",
		rejectsUnpinnedPublicDescriptor,
	);
}

/**
 * Tests portable base64url encoding and strict malformed input rejection.
 */
function roundTripsBase64Url() {
	const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
	const encoded = bytesToBase64Url(bytes);

	expect(base64UrlToBytes(encoded)).toEqual(bytes);
	expect(encoded).not.toMatch(/[+/=]/);
	expect(() => base64UrlToBytes("a")).toThrow("base64url");
}

/**
 * Tests credential encoding and verification across a full round trip.
 */
async function roundTripsCredential() {
	const rendered = await issueTestCredential("environment", "demo", "dev");
	const parsed = await parseCredential(rendered, {
		issuerPublicKey: TEST_ISSUER_PUBLIC_KEY,
	});

	expect(parsed.payload.type).toBe("environment");
	expect(parsed.payload.project).toBe("demo");
	expect(parsed.payload.environment).toBe("dev");
	expect(rendered).toMatch(
		/^secret_effects_v1_payload:.+_signature:.+_checksum:[0-9a-f]{32}_key:[0-9a-f]{128}$/,
	);
}

/**
 * Tests checksum rejection after credential key tampering.
 */
async function rejectsChangedCredential() {
	const rendered = await issueTestCredential("project", "demo", null);
	const index = rendered.lastIndexOf("_key:") + "_key:".length;
	const changed = `${rendered.slice(0, index)}${rendered[index] === "0" ? "1" : "0"}${rendered.slice(index + 1)}`;

	await expect(
		parseCredential(changed, { issuerPublicKey: TEST_ISSUER_PUBLIC_KEY }),
	).rejects.toThrow("checksum is invalid");
}

/**
 * Tests signature rejection after a checksum-preserving change.
 */
async function rejectsChangedSignature() {
	const rendered = await issueTestCredential("project", "demo", null);
	const match =
		/^(secret_effects_v1_payload:.+_signature:)(.+)_checksum:.+_key:(.+)$/.exec(
			rendered,
		);
	expect(match).not.toBeNull();
	const [, prefix = "", signature = "", key = ""] = match ?? [];
	const signatureBytes = bs58.decode(signature);
	signatureBytes[0] = (signatureBytes[0] ?? 0) ^ 1;
	const changedSignature = bs58.encode(signatureBytes);
	const withoutChecksum = `${prefix}${changedSignature}_key:${key}`;
	const checksum = bytesToHex(
		sha256(new TextEncoder().encode(withoutChecksum)),
	).slice(0, 32);
	const changed = `${prefix}${changedSignature}_checksum:${checksum}_key:${key}`;

	await expect(
		parseCredential(changed, { issuerPublicKey: TEST_ISSUER_PUBLIC_KEY }),
	).rejects.toThrow("signature is invalid");
}

/**
 * Tests issuer-key pinning against a self-signed credential with a foreign trust anchor.
 */
async function rejectsUnpinnedIssuer() {
	const rendered = await issueTestCredential("environment", "demo", "dev");

	await expect(
		parseCredential(rendered, { issuerPublicKey: "e".repeat(64) }),
	).rejects.toThrow("issuer key does not match the pinned trust anchor");
}

/**
 * Tests issuer-key pinning for a self-consistent public credential descriptor.
 */
async function rejectsUnpinnedPublicDescriptor() {
	const descriptor = exportPublicCredential(
		await parseCredential(
			await issueTestCredential("environment", "demo", "dev"),
			{
				issuerPublicKey: TEST_ISSUER_PUBLIC_KEY,
			},
		),
	);

	await expect(
		parsePublicCredential(descriptor, { issuerPublicKey: "e".repeat(64) }),
	).rejects.toThrow("issuer key does not match the pinned trust anchor");
	await expect(parsePublicCredential(descriptor)).resolves.toMatchObject({
		payload: { project: "demo" },
	});
}

/**
 * Groups encrypted environment bundle tests.
 */
function bundleTests() {
	it(
		"decrypts the full environment only for an included recipient",
		decryptsForIncludedRecipient,
	);
	it(
		"binds service acceptance and wrapped keys to their signed context",
		bindsSignedContext,
	);
}

/**
 * Tests encrypted bundle access for included and excluded recipients.
 */
async function decryptsForIncludedRecipient() {
	const author = await parseCredential(
		await issueTestCredential("project", "demo", null),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const runtime = await parseCredential(
		await issueTestCredential("environment", "demo", "production"),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const excluded = await parseCredential(
		await issueTestCredential("environment", "demo", "production"),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const draft = await sealBundle({
		project: "demo",
		environment: "production",
		schemaDigest: "a".repeat(64),
		values: { API_TOKEN: "arbitrary:value_with spaces" },
		recipients: [author, runtime].map((credential) => ({
			identifier: credential.payload.identifier,
			publicKey: credential.keys.decryptPublicKey,
		})),
		author,
	});
	const bundle = acceptTestBundle(draft);

	await expect(openBundle(bundle, runtime)).resolves.toEqual({
		API_TOKEN: "arbitrary:value_with spaces",
	});
	await expect(openBundle(bundle, excluded)).rejects.toThrow("not a recipient");
	expect(JSON.stringify(bundle)).not.toContain("arbitrary:value_with spaces");
}

/**
 * Tests service signatures and recipient wrapping context.
 */
async function bindsSignedContext() {
	const author = await parseCredential(
		await issueTestCredential("project", "demo", null),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const runtime = await parseCredential(
		await issueTestCredential("environment", "demo", "production"),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const other = await parseCredential(
		await issueTestCredential("environment", "demo", "production"),
		{ issuerPublicKey: TEST_ISSUER_PUBLIC_KEY },
	);
	const accepted = acceptTestBundle(
		await sealBundle({
			project: "demo",
			environment: "production",
			schemaDigest: "b".repeat(64),
			values: { VALUE: "protected" },
			recipients: [
				{
					identifier: runtime.payload.identifier,
					publicKey: runtime.keys.decryptPublicKey,
				},
			],
			author,
		}),
	);
	const relabeled = acceptTestBundle({
		...accepted,
		serviceSignature: null,
		recipients: accepted.recipients.map((recipient) => ({
			...recipient,
			identifier: other.payload.identifier,
		})),
	});

	await expect(openBundle(relabeled, other)).rejects.toThrow();
	await expect(
		openBundle({ ...accepted, project: "other" }, runtime),
	).rejects.toThrow("service signature is invalid");
}

/**
 * Creates a signed test credential for one scope.
 *
 * @param type - The credential type for the test scope.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @returns The rendered test credential.
 */
async function issueTestCredential(
	type: CredentialPayload["type"],
	project: string | null,
	environment: string | null,
): Promise<string> {
	const issuerPrivateKey = new Uint8Array(32).fill(7);
	const masterKey = generateMasterKey();
	const keys = deriveKeys(masterKey);
	const now = Date.now();
	const payload: CredentialPayload = {
		version: 1,
		api: "https://secrets.example.com",
		issuer: "testissuer",
		issuerPublicKey: bytesToHex(ed25519.getPublicKey(issuerPrivateKey)),
		type,
		project,
		environment,
		identifier: crypto.randomUUID().replaceAll("-", ""),
		authPublicKey: bytesToHex(keys.authPublicKey),
		decryptPublicKey:
			type === "project" || type === "environment"
				? bytesToHex(keys.decryptPublicKey)
				: null,
		issuedAt: now,
		notBefore: now - 1_000,
		expiresAt: null,
	};
	const payloadBytes = await encodeCredentialPayload(payload);
	return assembleCredential(
		payloadBytes,
		signPayload(payloadBytes, issuerPrivateKey),
		masterKey,
	);
}

/**
 * Adds a valid test service signature to a draft bundle.
 *
 * @param bundle - The encrypted bundle or test draft for the operation.
 * @returns The accepted test bundle with its service signature.
 */
function acceptTestBundle(bundle: SealedBundle): SealedBundle {
	const issuerPrivateKey = new Uint8Array(32).fill(7);
	return {
		...bundle,
		serviceSignature: bytesToBase64Url(
			signPayload(
				new TextEncoder().encode(canonicalJson(bundle)),
				issuerPrivateKey,
			),
		),
	};
}
