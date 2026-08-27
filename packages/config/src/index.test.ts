/**
 * Tests repository configuration, mirror resolution, and schema digests.
 *
 * @remarks
 * Responsibility: Owns regression coverage for default environments, mirror cycles, materialization, and stable manifests.
 *
 * Boundary: Uses deterministic sample configuration. It does not contact the service or use credentials.
 */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	defineConfig,
	materializeEnvironment,
	schemaDigest,
	schemaManifest,
	secret,
} from "./index.ts";

const config = defineConfig({
	project: "demo",
	environments: ["preview"],
	secrets: {
		API_URL: secret(z.url(), {
			mirror: { local: "dev", preview: "dev" },
		}),
		TOKEN: secret(z.string().min(8), { requiredIn: ["production"] }),
	},
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
	const cyclic = defineConfig({
		project: "demo",
		secrets: {
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
