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

describe("repository configuration", () => {
	it("keeps the three undeletable default environments", () => {
		expect(config.environments).toEqual([
			"local",
			"dev",
			"production",
			"preview",
		]);
	});

	it("materializes mirrors before runtime validation", () => {
		expect(
			materializeEnvironment(config, "local", {
				dev: { API_URL: "https://api.example.com" },
			}),
		).toEqual({ API_URL: "https://api.example.com" });
	});

	it("rejects mirror cycles", () => {
		const cyclic = defineConfig({
			project: "demo",
			secrets: {
				VALUE: secret(z.string(), { mirror: { local: "dev", dev: "local" } }),
			},
		});
		expect(() => materializeEnvironment(cyclic, "local", {})).toThrow("cyclic");
	});

	it("includes Zod JSON Schema in a stable manifest digest", async () => {
		const manifest = schemaManifest(config);
		expect(manifest.secrets.TOKEN?.jsonSchema).toMatchObject({
			type: "string",
			minLength: 8,
		});
		await expect(schemaDigest(config)).resolves.toMatch(/^[0-9a-f]{64}$/);
		await expect(schemaDigest(config)).resolves.toBe(
			await schemaDigest(config),
		);
	});
});
