import type { ZodType } from "zod";
import { z } from "zod";
import {
	DEFAULT_ENVIRONMENTS,
	ENVIRONMENT_KEY_PATTERN,
	assertMachineName,
} from "@secret-effects/protocol";

export interface SecretOptions {
	requiredIn?: readonly string[];
	mirror?: Readonly<Record<string, string>>;
}

export interface SecretDefinition<Schema extends ZodType = ZodType> {
	schema: Schema;
	requiredIn: readonly string[];
	mirror: Readonly<Record<string, string>>;
}

export type SecretRecord = Readonly<Record<string, SecretDefinition>>;

export interface SecretEffectsConfig<
	Secrets extends SecretRecord = SecretRecord,
> {
	project: string;
	environments: readonly string[];
	secrets: Secrets;
}

export type InferConfig<Config extends SecretEffectsConfig> = {
	-readonly [Key in keyof Config["secrets"]]: z.output<
		Config["secrets"][Key]["schema"]
	>;
};

export interface SecretEffectsManifest {
	version: 1;
	project: string;
	environments: readonly string[];
	secrets: Readonly<
		Record<
			string,
			{
				jsonSchema: unknown;
				requiredIn: readonly string[];
				mirror: Readonly<Record<string, string>>;
			}
		>
	>;
}

export function secret<Schema extends ZodType>(
	schema: Schema,
	options: SecretOptions = {},
): SecretDefinition<Schema> {
	return {
		schema,
		requiredIn: options.requiredIn ?? DEFAULT_ENVIRONMENTS,
		mirror: options.mirror ?? {},
	};
}

export function defineConfig<const Secrets extends SecretRecord>(input: {
	project: string;
	environments?: readonly string[];
	secrets: Secrets;
}): SecretEffectsConfig<Secrets> {
	assertMachineName(input.project, "The project name");
	const environments = [
		...new Set([...DEFAULT_ENVIRONMENTS, ...(input.environments ?? [])]),
	];
	for (const environment of environments) {
		assertMachineName(environment, "The environment name");
	}
	for (const [name, definition] of Object.entries(input.secrets)) {
		if (!ENVIRONMENT_KEY_PATTERN.test(name)) {
			throw new Error(`${name} is not a valid environment variable name.`);
		}
		for (const environment of definition.requiredIn) {
			if (!environments.includes(environment)) {
				throw new Error(
					`${name} requires the unknown environment ${environment}.`,
				);
			}
		}
		for (const [target, source] of Object.entries(definition.mirror)) {
			if (!environments.includes(target) || !environments.includes(source)) {
				throw new Error(
					`${name} has a mirror that references an unknown environment.`,
				);
			}
			if (target === source) {
				throw new Error(`${name} cannot mirror an environment to itself.`);
			}
		}
	}
	return { project: input.project, environments, secrets: input.secrets };
}

export function schemaForEnvironment<Config extends SecretEffectsConfig>(
	config: Config,
	environment: string,
): z.ZodObject<Record<string, ZodType>> {
	if (!config.environments.includes(environment)) {
		throw new Error(`The configuration does not declare ${environment}.`);
	}
	const shape: Record<string, ZodType> = {};
	for (const [name, definition] of Object.entries(config.secrets)) {
		shape[name] = definition.requiredIn.includes(environment)
			? definition.schema
			: definition.schema.optional();
	}
	return z.object(shape).strict();
}

export async function schemaDigest(
	config: SecretEffectsConfig,
): Promise<string> {
	const manifest = schemaManifest(config);
	const bytes = new TextEncoder().encode(canonicalJson(manifest));
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
}

export function schemaManifest(
	config: SecretEffectsConfig,
): SecretEffectsManifest {
	return {
		version: 1,
		project: config.project,
		environments: [...config.environments].sort(),
		secrets: Object.fromEntries(
			Object.entries(config.secrets)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([name, definition]) => [
					name,
					{
						jsonSchema: z.toJSONSchema(definition.schema),
						requiredIn: [...definition.requiredIn].sort(),
						mirror: Object.fromEntries(
							Object.entries(definition.mirror).sort(([left], [right]) =>
								left.localeCompare(right),
							),
						),
					},
				]),
		),
	};
}

export function materializeEnvironment<Config extends SecretEffectsConfig>(
	config: Config,
	environment: string,
	values: Readonly<
		Record<string, Readonly<Record<string, string | undefined>>>
	>,
): InferConfig<Config> {
	const schema = schemaForEnvironment(config, environment);
	const materialized: Record<string, string> = {};
	for (const [name, definition] of Object.entries(config.secrets)) {
		const value = resolveValue(
			name,
			environment,
			definition,
			values,
			new Set(),
		);
		if (value !== undefined) {
			materialized[name] = value;
		}
	}
	return schema.parse(materialized) as InferConfig<Config>;
}

function resolveValue(
	name: string,
	environment: string,
	definition: SecretDefinition,
	values: Readonly<
		Record<string, Readonly<Record<string, string | undefined>>>
	>,
	visited: Set<string>,
): string | undefined {
	const marker = `${name}:${environment}`;
	if (visited.has(marker)) {
		throw new Error(`${name} has a cyclic environment mirror.`);
	}
	const direct = values[environment]?.[name];
	if (direct !== undefined) {
		return direct;
	}
	const source = definition.mirror[environment];
	if (source === undefined) {
		return undefined;
	}
	visited.add(marker);
	const resolved = resolveValue(name, source, definition, values, visited);
	visited.delete(marker);
	return resolved;
}

function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort((left, right) => left.localeCompare(right))
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}
