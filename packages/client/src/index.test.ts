/**
 * Tests complete Secret Effects client loads and runtime source boundaries.
 *
 * @remarks
 * Responsibility: Owns regression coverage for signed retrieval, decryption, T3 validation, Worker bindings, conflicts, and request-local execution.
 *
 * Boundary: Uses generated credentials and encrypted bundles. It does not contact a deployed service or persist secret values.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, expectTypeOf, it, vi } from "vitest";
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
	parseCredential,
	sealBundle,
	signPayload,
} from "@secret-effects/crypto";
import {
	defineEnv,
	loadEnv,
	SecretEffectsClientError,
	schemaDigest,
	secret,
	z,
} from "./index.ts";

const issuerPrivateKey = new Uint8Array(32).fill(11);
const issuerPublicKey = bytesToHex(ed25519.getPublicKey(issuerPrivateKey));
const config = defineEnv({
	project: "demo",
	server: {
		API_TOKEN: secret(z.string().min(8)),
		PORT: z.coerce.number().int().positive(),
	},
	clientPrefix: "PUBLIC_",
	client: { PUBLIC_SITE_NAME: z.string().min(1) },
	shared: { NODE_ENV: z.enum(["development", "production", "test"]) },
});

describe("Secret Effects client", clientTests);

/**
 * Groups complete client load tests.
 */
function clientTests() {
	it(
		"loads one typed environment from Worker bindings",
		loadsWorkerEnvironment,
	);
	it(
		"selects an environment for a Project credential",
		loadsProjectEnvironment,
	);
	it("does not cache decrypted environments", doesNotCacheEnvironment);
	it("rejects a credential from another issuer", rejectsUnpinnedIssuer);
	it("rejects conflicting local secret values", rejectsSourceConflict);
	it(
		"rejects an oversized response before reading it",
		rejectsOversizedResponse,
	);
	it("rejects an oversized streamed response", rejectsOversizedStream);
	it("stops a stalled response at the request deadline", stopsStalledResponse);
}

/**
 * Tests signed retrieval, decryption, merge behavior, and T3 output inference.
 */
async function loadsWorkerEnvironment() {
	const fixture = await createFixture("first-secret");
	const env = await loadEnv(config, {
		runtimeEnv: {
			SECRET_EFFECTS_KEY: fixture.credential,
			PORT: "8787",
			PUBLIC_SITE_NAME: "Demo",
			NODE_ENV: "production",
			UNRELATED_BINDING: { fetch: vi.fn() },
		},
		fetch: fixture.fetch,
	});

	expect(env).toEqual({
		API_TOKEN: "first-secret",
		PORT: 8787,
		PUBLIC_SITE_NAME: "Demo",
		NODE_ENV: "production",
	});
	expect("SECRET_EFFECTS_KEY" in env).toBe(false);
	expectTypeOf(env).toEqualTypeOf<{
		API_TOKEN: string;
		PORT: number;
		PUBLIC_SITE_NAME: string;
		NODE_ENV: "development" | "production" | "test";
	}>();
	expect(fixture.fetch).toHaveBeenCalledWith(
		"https://secrets.example.com/v1/projects/demo/environments/production/bundle",
		expect.objectContaining({ headers: expect.any(Headers) }),
	);
}

/**
 * Tests explicit environment selection for a project-wide credential.
 */
async function loadsProjectEnvironment() {
	const credential = await issueTestCredential("project", "demo", null);
	const fixture = await createFixture("project-secret", credential);

	await expect(
		loadEnv(config, {
			credential,
			environment: "production",
			runtimeEnv: runtimeValues(),
			fetch: fixture.fetch,
		}),
	).resolves.toMatchObject({ API_TOKEN: "project-secret" });
}

/**
 * Tests that each load performs a new request and receives fresh plaintext.
 */
async function doesNotCacheEnvironment() {
	const first = await createFixture("first-secret");
	const second = await createFixture("second-secret", first.credential);
	const fetch = createServiceFetch([
		Response.json(first.bundle),
		Response.json(second.bundle),
	]);
	const options = {
		credential: first.credential,
		runtimeEnv: runtimeValues(),
		fetch,
	};

	await expect(loadEnv(config, options)).resolves.toMatchObject({
		API_TOKEN: "first-secret",
	});
	await expect(loadEnv(config, options)).resolves.toMatchObject({
		API_TOKEN: "second-secret",
	});
	expect(fetch).toHaveBeenCalledTimes(4);
}

/**
 * Tests rejection when the service issuer does not match the credential.
 */
async function rejectsUnpinnedIssuer() {
	const fixture = await createFixture("remote-secret");
	const fetch = createServiceFetch(
		[Response.json(fixture.bundle)],
		"e".repeat(64),
	);

	await expect(
		loadEnv(config, {
			credential: fixture.credential,
			runtimeEnv: runtimeValues(),
			fetch,
		}),
	).rejects.toMatchObject({ code: "CREDENTIAL" });
	expect(fetch).toHaveBeenCalledTimes(1);
}

/**
 * Tests rejection when local bindings and Secret Effects own the same value.
 */
async function rejectsSourceConflict() {
	const fixture = await createFixture("remote-secret");
	const error = await loadEnv(config, {
		credential: fixture.credential,
		runtimeEnv: { ...runtimeValues(), API_TOKEN: "local-secret" },
		fetch: fixture.fetch,
	}).catch((cause: unknown) => cause);

	expect(error).toMatchObject({
		_tag: "SecretEffectsClientError",
		code: "SOURCE_CONFLICT",
	});
	expect(error).toBeInstanceOf(SecretEffectsClientError);
	expect(String(error)).not.toContain("local-secret");
	expect(String(error)).not.toContain("remote-secret");
	expect(fixture.fetch).not.toHaveBeenCalled();
}

/**
 * Tests the encrypted response size boundary.
 */
async function rejectsOversizedResponse() {
	const credential = await issueTestCredential(
		"environment",
		"demo",
		"production",
	);
	const fetch = createServiceFetch([
		new Response("{}", {
			headers: { "content-length": String(2 * 1024 * 1024 + 1) },
		}),
	]);

	await expect(
		loadEnv(config, { credential, runtimeEnv: runtimeValues(), fetch }),
	).rejects.toMatchObject({ code: "RESPONSE" });
}

/**
 * Tests the size boundary when a response omits its declared length.
 */
async function rejectsOversizedStream() {
	const credential = await issueTestCredential(
		"environment",
		"demo",
		"production",
	);
	const fetch = createServiceFetch([
		new Response(new Uint8Array(2 * 1024 * 1024 + 1)),
	]);

	await expect(
		loadEnv(config, { credential, runtimeEnv: runtimeValues(), fetch }),
	).rejects.toMatchObject({ code: "RESPONSE" });
}

/**
 * Tests that the request deadline also bounds response body reads.
 */
async function stopsStalledResponse() {
	const credential = await issueTestCredential(
		"environment",
		"demo",
		"production",
	);
	const fetch = createServiceFetch([
		new Response(
			new ReadableStream({
				start: () => undefined,
			}),
		),
	]);

	await expect(
		loadEnv(config, {
			credential,
			runtimeEnv: runtimeValues(),
			fetch,
			timeoutMs: 5,
		}),
	).rejects.toMatchObject({ code: "RESPONSE" });
	expect(fetch).toHaveBeenCalledWith(
		expect.any(String),
		expect.objectContaining({ signal: expect.any(AbortSignal) }),
	);
}

/**
 * Creates one accepted encrypted bundle and its fetch implementation.
 *
 * @param value - The secret value to encrypt for the runtime credential.
 * @param existingCredential - The optional credential that must receive the bundle.
 * @returns The environment credential and one-use response implementation.
 */
async function createFixture(value: string, existingCredential?: string) {
	const author = await parseCredential(
		await issueTestCredential("project", "demo", null),
	);
	const credential =
		existingCredential ??
		(await issueTestCredential("environment", "demo", "production"));
	const runtime = await parseCredential(credential);
	const draft = await sealBundle({
		project: "demo",
		environment: "production",
		schemaDigest: await schemaDigest(config),
		values: { API_TOKEN: value },
		recipients: [
			{
				identifier: runtime.payload.identifier,
				publicKey: runtime.keys.decryptPublicKey,
			},
		],
		author,
	});
	const bundle = acceptTestBundle(draft);
	return {
		bundle,
		credential,
		fetch: createServiceFetch([Response.json(bundle)]),
	};
}

/**
 * Creates a service fetch implementation with issuer and bundle responses.
 *
 * @param bundleResponses - The ordered encrypted bundle responses for client loads.
 * @param trustedIssuerPublicKey - The issuer key returned by the well-known endpoint.
 * @returns The mock service fetch implementation.
 */
function createServiceFetch(
	bundleResponses: Response[],
	trustedIssuerPublicKey = issuerPublicKey,
) {
	const remainingBundles = [...bundleResponses];
	/**
	 * Returns the issuer record or the next encrypted bundle response.
	 *
	 * @param input - The service request URL or request object.
	 * @returns The matching service response.
	 * @throws {@link Error} When no bundle response remains.
	 */
	async function request(
		input: Parameters<typeof globalThis.fetch>[0],
	): Promise<Response> {
		const url = input instanceof Request ? input.url : String(input);
		if (url.endsWith("/.well-known/secret-effects")) {
			return Response.json({
				version: 1,
				issuerPublicKey: trustedIssuerPublicKey,
			});
		}
		const response = remainingBundles.shift();
		if (response === undefined) {
			throw new Error("No test bundle response remains.");
		}
		return response;
	}
	return vi.fn<typeof globalThis.fetch>().mockImplementation(request);
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
	const masterKey = generateMasterKey();
	const keys = deriveKeys(masterKey);
	const now = Date.now();
	const payload: CredentialPayload = {
		version: 1,
		api: "https://secrets.example.com",
		issuer: "testissuer",
		issuerPublicKey,
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
 * Adds a valid service signature to one draft bundle.
 *
 * @param bundle - The encrypted draft bundle.
 * @returns The accepted bundle with its service signature.
 */
function acceptTestBundle(bundle: SealedBundle): SealedBundle {
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

/**
 * Returns valid local runtime values for the shared client configuration.
 *
 * @returns The local runtime record.
 */
function runtimeValues() {
	return {
		PORT: "8787",
		PUBLIC_SITE_NAME: "Demo",
		NODE_ENV: "production",
	};
}
