/**
 * Defines and validates Secret Effects client configuration.
 *
 * @remarks
 * Responsibility: Owns environment-aware runtime schemas, secret definitions, mirror resolution, and stable manifest digests.
 *
 * Boundary: Accepts Zod schemas and plain secret values. It does not read credentials, contact the service, or decrypt bundles.
 */
import type { ZodType } from "zod";
import { z } from "zod";
import {
	DEFAULT_ENVIRONMENTS,
	ENVIRONMENT_KEY_PATTERN,
	assertMachineName,
	canonicalJson,
} from "@secret-effects/protocol";

const SECRET_DEFINITION = Symbol("secret-effects-secret-definition");
const CREDENTIAL_NAME = "SECRET_EFFECTS_KEY";

export interface SecretOptions<
	RequiredIn extends readonly string[] = readonly string[],
> {
	requiredIn?: RequiredIn;
	mirror?: Readonly<Record<string, string>>;
}

export interface SecretDefinition<
	Schema extends ZodType = ZodType,
	RequiredIn extends readonly string[] = readonly string[],
> {
	readonly [SECRET_DEFINITION]: true;
	schema: Schema;
	requiredIn: RequiredIn;
	mirror: Readonly<Record<string, string>>;
}

export type RuntimeSchemaRecord = Readonly<Record<string, ZodType>>;
export type ServerDefinition = ZodType | SecretDefinition;
export type ServerRecord = Readonly<Record<string, ServerDefinition>>;
export type SecretRecord = Readonly<Record<string, SecretDefinition>>;

export interface SecretEffectsConfig<
	Server extends ServerRecord = ServerRecord,
	Client extends RuntimeSchemaRecord = RuntimeSchemaRecord,
	Shared extends RuntimeSchemaRecord = RuntimeSchemaRecord,
	Environments extends readonly string[] = readonly string[],
> {
	project: string;
	environments: Environments;
	server: Server;
	client: Client;
	shared: Shared;
	clientPrefix?: string;
	secretDefinitions: SecretRecord;
}

type InferDefinition<Definition, Environment extends string> =
	Definition extends SecretDefinition<
		infer Schema,
		infer RequiredIn extends readonly string[]
	>
		? [Environment] extends [RequiredIn[number]]
			? z.output<Schema>
			: z.output<Schema> | undefined
		: Definition extends ZodType
			? z.output<Definition>
			: never;

type InferRecord<
	Definitions extends Readonly<Record<string, unknown>>,
	Environment extends string,
> = {
	-readonly [Key in keyof Definitions]: InferDefinition<
		Definitions[Key],
		Environment
	>;
};

type InferSecretRecord<
	Definitions extends ServerRecord,
	Environment extends string,
> = {
	-readonly [
		Key in keyof Definitions as Definitions[Key] extends SecretDefinition
			? Key
			: never
	]: InferDefinition<Definitions[Key], Environment>;
};

type Simplify<Value> = { [Key in keyof Value]: Value[Key] };

export type InferEnv<
	Config extends SecretEffectsConfig,
	Environment extends Config["environments"][number] =
		Config["environments"][number],
> =
	Config extends SecretEffectsConfig<infer Server, infer Client, infer Shared>
		? Simplify<
				InferRecord<Server, Environment> &
					InferRecord<Client, Environment> &
					InferRecord<Shared, Environment>
			>
		: never;

export type InferSecrets<
	Config extends SecretEffectsConfig,
	Environment extends Config["environments"][number] =
		Config["environments"][number],
> =
	Config extends SecretEffectsConfig<
		infer Server,
		RuntimeSchemaRecord,
		RuntimeSchemaRecord
	>
		? Simplify<InferSecretRecord<Server, Environment>>
		: never;

type DefaultEnvironment = (typeof DEFAULT_ENVIRONMENTS)[number];
type ConfiguredEnvironments<Additional extends readonly string[]> = readonly (
	| DefaultEnvironment
	| Additional[number]
)[];

type RequiredEnvironments<Options extends SecretOptions> = Options extends {
	requiredIn: infer RequiredIn extends readonly string[];
}
	? RequiredIn
	: typeof DEFAULT_ENVIRONMENTS;

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

export { z };

/**
 * Creates one normalized Secret Effects definition.
 *
 * @typeParam Schema - The Zod schema type for the secret value.
 * @typeParam Options - The literal requirement and mirror options for the secret.
 * @param schema - The Zod schema that validates the decrypted value.
 * @param options - The environment requirements and mirror mappings for the secret.
 * @returns The normalized secret definition.
 */
export function secret<
	Schema extends ZodType,
	const Options extends SecretOptions = {},
>(
	schema: Schema,
	options: Options = {} as Options,
): SecretDefinition<Schema, RequiredEnvironments<Options>> {
	return {
		[SECRET_DEFINITION]: true,
		schema,
		requiredIn: (options.requiredIn ??
			DEFAULT_ENVIRONMENTS) as RequiredEnvironments<Options>,
		mirror: options.mirror ?? {},
	};
}

/**
 * Validates and normalizes one repository environment configuration.
 *
 * @typeParam Server - The server schema and Secret Effects definitions.
 * @typeParam Environments - The additional environment names declared by the repository.
 * @typeParam Client - The client schema definitions.
 * @typeParam Shared - The shared schema definitions.
 * @param input - The project, environment, and runtime schema configuration.
 * @returns The normalized client configuration.
 * @throws {@link Error} When configuration data violates a required constraint.
 */
export function defineEnv<
	const Server extends ServerRecord,
	const Environments extends readonly string[] = readonly [],
	const Client extends RuntimeSchemaRecord = {},
	const Shared extends RuntimeSchemaRecord = {},
>(input: {
	project: string;
	environments?: Environments;
	server: Server;
	client?: Client;
	shared?: Shared;
	clientPrefix?: string;
}): SecretEffectsConfig<
	Server,
	Client,
	Shared,
	ConfiguredEnvironments<Environments>
> {
	assertMachineName(input.project, "The project name");
	const environments = [
		...new Set([...DEFAULT_ENVIRONMENTS, ...(input.environments ?? [])]),
	];
	for (const environment of environments) {
		assertMachineName(environment, "The environment name");
	}
	const client = input.client ?? ({} as Client);
	const shared = input.shared ?? ({} as Shared);
	validateSchemaNames(input.server, client, shared);
	validateClientPrefix(input.clientPrefix, input.server, client);
	const secretDefinitions: Record<string, SecretDefinition> = {};
	for (const [name, definition] of Object.entries(input.server)) {
		if (!isSecretDefinition(definition)) continue;
		validateSecretDefinition(name, definition, environments);
		secretDefinitions[name] = definition;
	}
	return {
		project: input.project,
		environments: environments as ConfiguredEnvironments<Environments>,
		server: input.server,
		client,
		shared,
		...(input.clientPrefix === undefined
			? {}
			: { clientPrefix: input.clientPrefix }),
		secretDefinitions,
	};
}

/**
 * Builds the server schema for one configured environment.
 *
 * @param config - The repository configuration that defines the environment.
 * @param environment - The environment selected by the runtime credential.
 * @returns The server schema with environment-specific secret requirements.
 * @throws {@link Error} When the configuration does not declare the environment.
 */
export function serverSchemaForEnvironment(
	config: SecretEffectsConfig,
	environment: string,
): RuntimeSchemaRecord {
	if (!config.environments.includes(environment)) {
		throw new Error(`The configuration does not declare ${environment}.`);
	}
	return Object.fromEntries(
		Object.entries(config.server).map(([name, definition]) => [
			name,
			isSecretDefinition(definition)
				? definition.requiredIn.includes(environment)
					? definition.schema
					: definition.schema.optional()
				: definition,
		]),
	);
}

/**
 * Builds the strict Zod schema for one configured secret environment.
 *
 * @param config - The repository configuration that defines the environment.
 * @param environment - The environment selected for secret validation.
 * @returns The strict secret schema.
 * @throws {@link Error} When the configuration does not declare the environment.
 */
export function schemaForEnvironment(
	config: SecretEffectsConfig,
	environment: string,
): z.ZodObject<Record<string, ZodType>> {
	if (!config.environments.includes(environment)) {
		throw new Error(`The configuration does not declare ${environment}.`);
	}
	const shape: Record<string, ZodType> = {};
	for (const [name, definition] of Object.entries(config.secretDefinitions)) {
		shape[name] = definition.requiredIn.includes(environment)
			? definition.schema
			: definition.schema.optional();
	}
	return z.object(shape).strict();
}

/**
 * Computes the stable SHA-256 digest for a repository secret schema.
 *
 * @param config - The repository configuration that defines the secrets.
 * @returns The lowercase schema digest.
 */
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

/**
 * Builds a stable manifest from one repository secret configuration.
 *
 * @param config - The repository configuration that defines the secrets.
 * @returns The stable repository schema manifest.
 */
export function schemaManifest(
	config: SecretEffectsConfig,
): SecretEffectsManifest {
	return {
		version: 1,
		project: config.project,
		environments: [...config.environments].sort(),
		secrets: Object.fromEntries(
			Object.entries(config.secretDefinitions)
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

/**
 * Resolves mirrors and validates one complete secret environment.
 *
 * @typeParam Config - The repository configuration that determines the secret result.
 * @typeParam Environment - The configured environment selected for materialization.
 * @param config - The repository configuration that defines the secrets.
 * @param environment - The environment selected for publication.
 * @param values - The nested environment and secret values to resolve.
 * @returns The validated secret values for the environment.
 */
export function materializeEnvironment<
	Config extends SecretEffectsConfig,
	const Environment extends Config["environments"][number],
>(
	config: Config,
	environment: Environment,
	values: Readonly<
		Record<string, Readonly<Record<string, string | undefined>>>
	>,
): InferSecrets<Config, Environment> {
	const schema = schemaForEnvironment(config, environment);
	const materialized: Record<string, string> = {};
	for (const [name, definition] of Object.entries(config.secretDefinitions)) {
		const resolved = resolveSecret(
			name,
			environment,
			definition,
			values,
			new Set(),
		);
		if (resolved !== undefined) materialized[name] = resolved;
	}
	return schema.parse(materialized) as InferSecrets<Config, Environment>;
}

/**
 * Tests whether a server definition marks a Secret Effects value.
 *
 * @param definition - The runtime schema or secret definition to test.
 * @returns True when the definition selects Secret Effects as its source.
 */
function isSecretDefinition(
	definition: ServerDefinition,
): definition is SecretDefinition {
	return SECRET_DEFINITION in definition;
}

/**
 * Validates all environment variable names and rejects duplicate schema ownership.
 *
 * @param server - The server-side schema definitions.
 * @param client - The client-side schema definitions.
 * @param shared - The shared schema definitions.
 * @throws {@link Error} When a name is invalid or belongs to multiple schema groups.
 */
function validateSchemaNames(
	server: ServerRecord,
	client: RuntimeSchemaRecord,
	shared: RuntimeSchemaRecord,
): void {
	const owners = new Map<string, string>();
	for (const [owner, definitions] of [
		["server", server],
		["client", client],
		["shared", shared],
	] as const) {
		for (const name of Object.keys(definitions)) {
			if (!ENVIRONMENT_KEY_PATTERN.test(name)) {
				throw new Error(`${name} is not a valid environment variable name.`);
			}
			if (name === CREDENTIAL_NAME) {
				throw new Error(
					`${CREDENTIAL_NAME} is reserved for client credentials.`,
				);
			}
			const existingOwner = owners.get(name);
			if (existingOwner !== undefined) {
				throw new Error(
					`${name} belongs to both the ${existingOwner} and ${owner} schemas.`,
				);
			}
			owners.set(name, owner);
		}
	}
}

/**
 * Validates the client prefix against all client and server names.
 *
 * @param clientPrefix - The prefix reserved for browser-readable values.
 * @param server - The private server schema definitions.
 * @param client - The browser-readable schema definitions.
 * @throws {@link Error} When the prefix is missing or conflicts with a schema name.
 */
function validateClientPrefix(
	clientPrefix: string | undefined,
	server: ServerRecord,
	client: RuntimeSchemaRecord,
): void {
	const clientNames = Object.keys(client);
	if (clientNames.length > 0 && !clientPrefix) {
		throw new Error("clientPrefix is required when client schemas exist.");
	}
	if (!clientPrefix) return;
	for (const name of clientNames) {
		if (!name.startsWith(clientPrefix)) {
			throw new Error(`${name} does not start with ${clientPrefix}.`);
		}
	}
	for (const name of Object.keys(server)) {
		if (name.startsWith(clientPrefix)) {
			throw new Error(`${name} is a server value with the client prefix.`);
		}
	}
}

/**
 * Validates one secret's environment requirements and mirror sources.
 *
 * @param name - The environment variable name for the secret.
 * @param definition - The secret schema and environment rules.
 * @param environments - All environments declared by the repository.
 * @throws {@link Error} When a requirement or mirror references an invalid environment.
 */
function validateSecretDefinition(
	name: string,
	definition: SecretDefinition,
	environments: readonly string[],
): void {
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

/**
 * Resolves one direct or mirrored secret without cycles.
 *
 * @param name - The environment variable name to resolve.
 * @param environment - The environment that needs the secret.
 * @param definition - The secret schema and mirror rules.
 * @param values - The available values grouped by environment.
 * @param visited - The active mirror path used to detect cycles.
 * @returns The resolved secret, or undefined when no source contains it.
 * @throws {@link Error} When the mirror path contains a cycle.
 */
function resolveSecret(
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
	if (direct !== undefined) return direct;
	const source = definition.mirror[environment];
	if (source === undefined) return undefined;
	visited.add(marker);
	const resolved = resolveSecret(name, source, definition, values, visited);
	visited.delete(marker);
	return resolved;
}
