import { createEnv } from "@t3-oss/env-core";
import * as Schema from "effect/Schema";
import type { SecretEffectsConfig, InferConfig } from "@secret-effects/config";
import { schemaDigest, schemaForEnvironment } from "@secret-effects/config";
import {
	openBundle,
	parseCredential,
	signRequest,
} from "@secret-effects/crypto";
import { SealedBundle, assertMachineName } from "@secret-effects/protocol";

export interface LoadEnvOptions {
	credential?: string;
	fetch?: typeof globalThis.fetch;
}

export async function loadEnv<Config extends SecretEffectsConfig>(
	config: Config,
	options: LoadEnvOptions = {},
): Promise<InferConfig<Config>> {
	const rendered = options.credential ?? readCredentialFromRuntime();
	const credential = await parseCredential(rendered);
	if (
		credential.payload.type !== "environment" &&
		credential.payload.type !== "project"
	) {
		throw new Error(
			"The runtime client requires an Environment or Project credential.",
		);
	}
	if (credential.payload.project !== config.project) {
		throw new Error(
			"The credential project does not match the repository configuration.",
		);
	}
	const environment = credential.payload.environment;
	if (environment === null) {
		throw new Error("The credential does not select an environment.");
	}
	assertMachineName(environment, "The credential environment");
	const api = new URL(credential.payload.api);
	if (
		api.protocol !== "https:" ||
		api.pathname !== "/" ||
		api.search !== "" ||
		api.hash !== ""
	) {
		throw new Error("The credential API must contain an HTTPS origin.");
	}
	const path = `/v1/projects/${encodeURIComponent(config.project)}/environments/${encodeURIComponent(environment)}/bundle`;
	const headers = await signRequest(credential, "GET", path, new Uint8Array());
	const response = await (options.fetch ?? globalThis.fetch)(
		`${api.origin}${path}`,
		{
			headers,
		},
	);
	if (!response.ok) {
		throw new Error(`Secret Effects returned HTTP ${response.status}.`);
	}
	const bundle = Schema.decodeUnknownSync(SealedBundle)(await response.json());
	const expectedSchemaDigest = await schemaDigest(config);
	if (
		bundle.project !== config.project ||
		bundle.environment !== environment ||
		bundle.schemaDigest !== expectedSchemaDigest
	) {
		throw new Error(
			"The bundle does not match the requested repository scope.",
		);
	}
	const values = await openBundle(bundle, credential);
	const schema = schemaForEnvironment(config, environment);
	const runtimeEnv = Object.fromEntries(
		Object.entries(values).filter(([, value]) => value !== ""),
	);
	const env = createEnv({
		server: Object.fromEntries(
			Object.entries(config.secrets).map(([name, definition]) => [
				name,
				definition.requiredIn.includes(environment)
					? definition.schema
					: definition.schema.optional(),
			]),
		),
		runtimeEnv,
		emptyStringAsUndefined: true,
	});
	return schema.parse(env) as InferConfig<Config>;
}

function readCredentialFromRuntime(): string {
	const value =
		typeof process === "undefined" ? undefined : process.env.SECRET_EFFECTS_KEY;
	if (typeof value !== "string" || value.length === 0) {
		throw new Error("SECRET_EFFECTS_KEY is not configured.");
	}
	return value;
}
