/**
 * Tests repository configuration, mirror resolution, and schema digests.
 *
 * @remarks
 * Responsibility: Owns regression coverage for default environments, mirror cycles, materialization, and stable manifests.
 *
 * Boundary: Uses deterministic sample configuration. It does not contact the service or use credentials.
 */
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	defineEnv,
	type InferEnv,
	type InferSecrets,
	materializeEnvironment,
	schemaDigest,
	schemaManifest,
	secret,
	z,
} from "./config.ts";

const config = defineEnv({
	project: "demo",
	environments: ["preview"],
	server: {
		API_URL: secret(z.url(), {
			mirror: { local: "dev", preview: "dev" },
		}),
		TOKEN: secret(z.string().min(8), { requiredIn: ["production"] }),
		PORT: z.coerce.number().int().positive(),
	},
	clientPrefix: "PUBLIC_",
	client: { PUBLIC_APP_NAME: z.string() },
	shared: { NODE_ENV: z.enum(["development", "production", "test"]) },
});

describe("repository configuration", repositoryConfigurationTests);

/**
 * Groups repository configuration tests.
 */
function repositoryConfigurationTests() {
	it(
		"keeps the three undeletable default environments",
		keepsDefaultEnvironments,
	);
	it("materializes mirrors before runtime validation", materializesMirrors);
	it("rejects mirror cycles", rejectsMirrorCycles);
	it(
		"includes Zod JSON Schema in a stable manifest digest",
		includesStableSchemaDigest,
	);
	it("infers all validated values from one definition", infersEnvironment);
	it("reserves the client credential name", reservesCredentialName);
}

/**
 * Tests the fixed default environment set.
 */
function keepsDefaultEnvironments() {
	expect(config.environments).toEqual([
		"local",
		"dev",
		"production",
		"preview",
	]);
}

/**
 * Tests environment mirror resolution before validation.
 */
function materializesMirrors() {
	expect(
		materializeEnvironment(config, "local", {
			dev: { API_URL: "https://api.example.com" },
		}),
	).toEqual({ API_URL: "https://api.example.com" });
}

/**
 * Tests rejection of a cyclic environment mirror.
 */
function rejectsMirrorCycles() {
	const cyclic = defineEnv({
		project: "demo",
		server: {
			VALUE: secret(z.string(), { mirror: { local: "dev", dev: "local" } }),
		},
	});
	expect(() => materializeEnvironment(cyclic, "local", {})).toThrow("cyclic");
}

/**
 * Tests stable schema manifests and digests.
 */
async function includesStableSchemaDigest() {
	const manifest = schemaManifest(config);
	expect(manifest.secrets.TOKEN?.jsonSchema).toMatchObject({
		type: "string",
		minLength: 8,
	});
	await expect(schemaDigest(config)).resolves.toMatch(/^[0-9a-f]{64}$/);
	await expect(schemaDigest(config)).resolves.toBe(await schemaDigest(config));
}

/**
 * Tests the combined server, client, shared, and secret output types.
 */
function infersEnvironment() {
	type Environment = InferEnv<typeof config>;
	type ProductionEnvironment = InferEnv<typeof config, "production">;
	type Secrets = InferSecrets<typeof config>;
	expectTypeOf<Environment>().toEqualTypeOf<{
		API_URL: string | undefined;
		TOKEN: string | undefined;
		PORT: number;
		PUBLIC_APP_NAME: string;
		NODE_ENV: "development" | "production" | "test";
	}>();
	expectTypeOf<ProductionEnvironment>().toEqualTypeOf<{
		API_URL: string;
		TOKEN: string;
		PORT: number;
		PUBLIC_APP_NAME: string;
		NODE_ENV: "development" | "production" | "test";
	}>();
	expectTypeOf<Secrets>().toEqualTypeOf<{
		API_URL: string | undefined;
		TOKEN: string | undefined;
	}>();
}

/**
 * Tests that a schema cannot expose the runtime credential.
 */
function reservesCredentialName() {
	expect(() =>
		defineEnv({
			project: "demo",
			server: { SECRET_EFFECTS_KEY: z.string() },
		}),
	).toThrow("reserved");
}
