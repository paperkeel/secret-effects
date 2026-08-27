import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import type { CredentialPayload } from "@secret-effects/protocol";
import {
	assembleCredential,
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
		const changed = rendered.replace("_key:", "_key:0");

		await expect(parseCredential(changed)).rejects.toThrow("invalid shape");
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
		const bundle = await sealBundle({
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

		await expect(openBundle(bundle, runtime)).resolves.toEqual({
			API_TOKEN: "arbitrary:value_with spaces",
		});
		await expect(openBundle(bundle, excluded)).rejects.toThrow(
			"not a recipient",
		);
		expect(JSON.stringify(bundle)).not.toContain("arbitrary:value_with spaces");
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
