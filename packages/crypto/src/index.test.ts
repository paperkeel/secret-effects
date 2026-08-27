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
	bytesToBase64Url,
	bytesToHex,
	deriveKeys,
	encodeCredentialPayload,
	generateMasterKey,
	openBundle,
	parseCredential,
	sealBundle,
	signPayload,
} from "./index.ts";

describe("Secret Effects credentials", () => {
	it("round-trips the signed self-contained credential", async () => {
		const rendered = await issueTestCredential("environment", "demo", "dev");
		const parsed = await parseCredential(rendered);

		expect(parsed.payload.type).toBe("environment");
		expect(parsed.payload.project).toBe("demo");
		expect(parsed.payload.environment).toBe("dev");
		expect(rendered).toMatch(
			/^secret_effects_v1_payload:.+_signature:.+_checksum:[0-9a-f]{32}_key:[0-9a-f]{128}$/,
		);
	});

	it("rejects a credential that changed after issuance", async () => {
		const rendered = await issueTestCredential("project", "demo", null);
		const index = rendered.lastIndexOf("_key:") + "_key:".length;
		const changed = `${rendered.slice(0, index)}${rendered[index] === "0" ? "1" : "0"}${rendered.slice(index + 1)}`;

		await expect(parseCredential(changed)).rejects.toThrow(
			"checksum is invalid",
		);
	});

	it("rejects a changed signature after a valid checksum", async () => {
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

		await expect(parseCredential(changed)).rejects.toThrow(
			"signature is invalid",
		);
	});
});

describe("encrypted environment bundles", () => {
	it("decrypts the full environment only for an included recipient", async () => {
		const author = await parseCredential(
			await issueTestCredential("project", "demo", null),
		);
		const runtime = await parseCredential(
			await issueTestCredential("environment", "demo", "production"),
		);
		const excluded = await parseCredential(
			await issueTestCredential("environment", "demo", "production"),
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
		await expect(openBundle(bundle, excluded)).rejects.toThrow(
			"not a recipient",
		);
		expect(JSON.stringify(bundle)).not.toContain("arbitrary:value_with spaces");
	});

	it("binds service acceptance and wrapped keys to their signed context", async () => {
		const author = await parseCredential(
			await issueTestCredential("project", "demo", null),
		);
		const runtime = await parseCredential(
			await issueTestCredential("environment", "demo", "production"),
		);
		const other = await parseCredential(
			await issueTestCredential("environment", "demo", "production"),
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
	});
});

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
