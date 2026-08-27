/**
 * Loads one validated environment from Secret Effects and local runtime values.
 *
 * @remarks
 * Responsibility: Owns credential selection, issuer pinning, bounded bundle retrieval, scope validation, decryption, source merging, and T3 environment validation.
 *
 * Boundary: Accepts a repository configuration and runtime bindings. It does not publish, persist, cache, log, or expose secret values.
 */
import {
	createEnv,
	type EnvOptions,
	type StandardSchemaV1,
} from "@t3-oss/env-core";
import * as Data from "effect/Data";
import * as Schema from "effect/Schema";
import {
	openBundle,
	parseCredential,
	signRequest,
} from "@secret-effects/crypto";
import { SealedBundle, assertMachineName } from "@secret-effects/protocol";
import {
	type InferEnv,
	type RuntimeSchemaRecord,
	type SecretEffectsConfig,
	schemaDigest,
	schemaForEnvironment,
	serverSchemaForEnvironment,
} from "./config.js";

export {
	defineEnv,
	materializeEnvironment,
	schemaDigest,
	schemaManifest,
	secret,
	z,
} from "./config.js";
export type {
	InferEnv,
	InferSecrets,
	RuntimeSchemaRecord,
	SecretDefinition,
	SecretEffectsConfig,
	SecretEffectsManifest,
	SecretOptions,
	ServerDefinition,
	ServerRecord,
} from "./config.js";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const CREDENTIAL_NAME = "SECRET_EFFECTS_KEY";

export type RuntimeEnv = Readonly<
	Record<string, string | number | boolean | undefined>
>;

export type SecretEffectsClientErrorCode =
	| "CREDENTIAL"
	| "DECRYPTION"
	| "INTERNAL"
	| "REQUEST"
	| "RESPONSE"
	| "SCOPE"
	| "SOURCE_CONFLICT"
	| "VALIDATION";

export class SecretEffectsClientError extends Data.TaggedError(
	"SecretEffectsClientError",
)<{
	readonly code: SecretEffectsClientErrorCode;
	readonly message: string;
}> {}

export interface LoadEnvOptions<Environment extends string = string> {
	credential?: string;
	environment?: Environment;
	fetch?: typeof globalThis.fetch;
	runtimeEnv?: object;
	timeoutMs?: number;
}

type RuntimeCreateEnvOptions = EnvOptions<
	string | undefined,
	RuntimeSchemaRecord,
	RuntimeSchemaRecord,
	RuntimeSchemaRecord,
	[],
	StandardSchemaV1<{}, Readonly<Record<string, unknown>>>
>;

/**
 * Loads, decrypts, merges, and validates one configured runtime environment.
 *
 * @typeParam Config - The repository configuration that determines the result shape.
 * @typeParam Environment - The configured environment selected by the caller or credential.
 * @param config - The repository configuration that defines the environment.
 * @param options - The optional credential, environment, fetch implementation, runtime bindings, and timeout.
 * @returns The validated environment values.
 * @throws {@link SecretEffectsClientError} When the client cannot produce a valid environment.
 */
export async function loadEnv<
	Config extends SecretEffectsConfig,
	const Environment extends Config["environments"][number] =
		Config["environments"][number],
>(
	config: Config,
	options: LoadEnvOptions<Environment> = {},
): Promise<InferEnv<Config, Environment>> {
	try {
		return await loadValidatedEnv(config, options);
	} catch (error) {
		if (error instanceof SecretEffectsClientError) throw error;
		throw clientError(
			"INTERNAL",
			"Secret Effects could not load the environment.",
		);
	}
}

/**
 * Performs one uncached environment load within the public error boundary.
 *
 * @typeParam Config - The repository configuration that determines the result shape.
 * @param config - The repository configuration that defines the environment.
 * @param options - The optional credential, fetch implementation, and runtime bindings.
 * @returns The validated environment values.
 * @throws {@link SecretEffectsClientError} When a load step fails.
 */
async function loadValidatedEnv<Config extends SecretEffectsConfig>(
	config: Config,
	options: LoadEnvOptions<Config["environments"][number]>,
): Promise<InferEnv<Config>> {
	const runtimeEnv = normalizeRuntimeEnv(
		options.runtimeEnv ?? defaultRuntimeEnv(),
	);
	const rendered = readCredential(options.credential, runtimeEnv);
	rejectSourceConflicts(config, runtimeEnv);
	let candidate;
	try {
		candidate = await parseCredential(rendered);
	} catch {
		throw clientError(
			"CREDENTIAL",
			"The Secret Effects credential is invalid.",
		);
	}
	if (
		candidate.payload.type !== "environment" &&
		candidate.payload.type !== "project"
	) {
		throw clientError(
			"CREDENTIAL",
			"The client requires an Environment or Project credential.",
		);
	}
	if (candidate.payload.project !== config.project) {
		throw clientError(
			"SCOPE",
			"The credential project does not match the client configuration.",
		);
	}
	if (
		candidate.payload.environment !== null &&
		options.environment !== undefined &&
		candidate.payload.environment !== options.environment
	) {
		throw clientError(
			"SCOPE",
			"The requested environment does not match the credential environment.",
		);
	}
	const environment =
		candidate.payload.environment ?? options.environment ?? null;
	if (environment === null) {
		throw clientError(
			"SCOPE",
			"The credential does not select an environment.",
		);
	}
	try {
		assertMachineName(environment, "The credential environment");
	} catch {
		throw clientError("SCOPE", "The credential environment is invalid.");
	}
	if (!config.environments.includes(environment)) {
		throw clientError(
			"SCOPE",
			"The client configuration does not declare the credential environment.",
		);
	}
	const api = validateApiOrigin(candidate.payload.api);
	const path = `/v1/projects/${formatPathSegment(config.project)}/environments/${formatPathSegment(environment)}/bundle`;
	const timeoutMs = validateTimeout(options.timeoutMs);
	const signal = AbortSignal.timeout(timeoutMs);
	const request = options.fetch ?? globalThis.fetch;
	const wellKnown = await fetchServiceWellKnown(api.origin, request, signal);
	let credential;
	try {
		credential = await parseCredential(rendered, {
			issuerPublicKey: wellKnown.issuerPublicKey,
			apiOrigin: api.origin,
		});
	} catch {
		throw clientError(
			"CREDENTIAL",
			"The Secret Effects credential does not match the service issuer.",
		);
	}
	let response: Response;
	try {
		const headers = await signRequest(
			credential,
			"GET",
			path,
			new Uint8Array(),
		);
		response = await request(`${api.origin}${path}`, { headers, signal });
	} catch {
		throw clientError("REQUEST", "The Secret Effects request failed.");
	}
	if (!response.ok) {
		throw clientError(
			"RESPONSE",
			`Secret Effects returned HTTP ${response.status}.`,
		);
	}
	const bundle = await readBundle(response, signal);
	let expectedSchemaDigest: string;
	try {
		expectedSchemaDigest = await schemaDigest(config);
	} catch {
		throw clientError(
			"VALIDATION",
			"The Secret Effects configuration is invalid.",
		);
	}
	if (
		bundle.project !== config.project ||
		bundle.environment !== environment ||
		bundle.schemaDigest !== expectedSchemaDigest
	) {
		throw clientError(
			"SCOPE",
			"The bundle does not match the requested project, environment, and schema.",
		);
	}
	let secrets: Record<string, string>;
	try {
		secrets = await openBundle(bundle, credential);
	} catch {
		throw clientError(
			"DECRYPTION",
			"The Secret Effects bundle could not be verified and decrypted.",
		);
	}
	try {
		schemaForEnvironment(config, environment).parse(secrets);
	} catch {
		throw clientError(
			"VALIDATION",
			"The decrypted Secret Effects values are invalid.",
		);
	}
	const mergedRuntimeEnv: RuntimeEnv = {
		...runtimeEnv,
		...secrets,
		[CREDENTIAL_NAME]: undefined,
	};
	const server = serverSchemaForEnvironment(config, environment);
	const createEnvOptions: RuntimeCreateEnvOptions = {
		server,
		client: config.client,
		shared: config.shared,
		clientPrefix: config.clientPrefix,
		runtimeEnv: mergedRuntimeEnv,
		emptyStringAsUndefined: true,
		isServer: true,
		onValidationError: throwValidationError,
	};
	const env = createEnv(createEnvOptions);
	return env as InferEnv<Config>;
}

/**
 * Validates one request deadline.
 *
 * @param value - The optional timeout in milliseconds.
 * @returns The validated timeout or the default timeout.
 * @throws {@link SecretEffectsClientError} When the timeout is invalid.
 */
function validateTimeout(value: number | undefined): number {
	const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
	if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
		throw clientError(
			"VALIDATION",
			"The Secret Effects timeout must be a positive integer.",
		);
	}
	return timeoutMs;
}

/**
 * Returns the process environment when a Node.js runtime provides it.
 *
 * @returns The process environment or an empty object in other runtimes.
 */
function defaultRuntimeEnv(): object {
	return typeof process === "undefined" ? {} : process.env;
}

/**
 * Copies supported primitive runtime bindings into a validation record.
 *
 * @param source - The Node.js environment or Worker bindings object.
 * @returns The enumerable primitive runtime values.
 */
function normalizeRuntimeEnv(source: object): RuntimeEnv {
	return Object.fromEntries(
		Object.entries(source).filter(
			(entry): entry is [string, string | number | boolean | undefined] =>
				entry[1] === undefined ||
				typeof entry[1] === "string" ||
				typeof entry[1] === "number" ||
				typeof entry[1] === "boolean",
		),
	);
}

/**
 * Selects the explicit or runtime Secret Effects credential.
 *
 * @param explicit - The credential supplied for this load.
 * @param runtimeEnv - The normalized runtime values.
 * @returns The selected nonempty credential.
 * @throws {@link SecretEffectsClientError} When no credential exists.
 */
function readCredential(
	explicit: string | undefined,
	runtimeEnv: RuntimeEnv,
): string {
	const value = explicit ?? runtimeEnv[CREDENTIAL_NAME];
	if (typeof value !== "string" || value.length === 0) {
		throw clientError("CREDENTIAL", `${CREDENTIAL_NAME} is not configured.`);
	}
	return value;
}

/**
 * Validates the credential API as a bare HTTPS origin.
 *
 * @param value - The API URL from the signed credential.
 * @returns The validated API URL.
 * @throws {@link SecretEffectsClientError} When the URL is not a bare HTTPS origin.
 */
function validateApiOrigin(value: string): URL {
	let api: URL;
	try {
		api = new URL(value);
	} catch {
		throw clientError("CREDENTIAL", "The credential API URL is invalid.");
	}
	if (
		api.protocol !== "https:" ||
		api.username !== "" ||
		api.password !== "" ||
		api.pathname !== "/" ||
		api.search !== "" ||
		api.hash !== ""
	) {
		throw clientError(
			"CREDENTIAL",
			"The credential API must contain a bare HTTPS origin.",
		);
	}
	return api;
}

interface ServiceWellKnown {
	issuerPublicKey: string;
}

/**
 * Fetches and validates the issuer record from one service origin.
 *
 * @param apiOrigin - The HTTPS service origin that hosts the well-known record.
 * @param fetchImpl - The HTTP client for the well-known request.
 * @param signal - The deadline signal shared with the bundle request.
 * @returns The validated service issuer record.
 * @throws {@link SecretEffectsClientError} When the request or record is invalid.
 */
async function fetchServiceWellKnown(
	apiOrigin: string,
	fetchImpl: typeof globalThis.fetch,
	signal: AbortSignal,
): Promise<ServiceWellKnown> {
	let response: Response;
	try {
		response = await fetchImpl(`${apiOrigin}/.well-known/secret-effects`, {
			signal,
		});
	} catch {
		throw clientError(
			"REQUEST",
			"The Secret Effects issuer record is unreachable.",
		);
	}
	if (!response.ok) {
		throw clientError(
			"RESPONSE",
			`The Secret Effects issuer record returned HTTP ${response.status}.`,
		);
	}
	let record: unknown;
	try {
		record = await response.json();
	} catch {
		throw clientError(
			"RESPONSE",
			"The Secret Effects issuer record is invalid.",
		);
	}
	if (
		typeof record !== "object" ||
		record === null ||
		!("version" in record) ||
		record.version !== 1 ||
		!("issuerPublicKey" in record) ||
		typeof record.issuerPublicKey !== "string" ||
		!/^[0-9a-f]{64}$/.test(record.issuerPublicKey)
	) {
		throw clientError(
			"RESPONSE",
			"The Secret Effects issuer record is invalid.",
		);
	}
	return { issuerPublicKey: record.issuerPublicKey };
}

/**
 * Reads and validates one bounded encrypted bundle response.
 *
 * @param response - The successful Secret Effects response.
 * @param signal - The deadline signal shared with the request.
 * @returns The validated encrypted bundle.
 * @throws {@link SecretEffectsClientError} When the body is too large or invalid.
 */
async function readBundle(
	response: Response,
	signal: AbortSignal,
): Promise<typeof SealedBundle.Type> {
	const declaredLength = response.headers.get("content-length");
	if (
		declaredLength !== null &&
		Number.parseInt(declaredLength, 10) > MAX_RESPONSE_BYTES
	) {
		throw clientError("RESPONSE", "The Secret Effects response is too large.");
	}
	if (response.body === null) {
		throw clientError("RESPONSE", "The Secret Effects response has no body.");
	}
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const result = await readChunk(reader, signal);
			if (result.done) break;
			length += result.value.byteLength;
			if (length > MAX_RESPONSE_BYTES) {
				await reader.cancel();
				throw clientError(
					"RESPONSE",
					"The Secret Effects response is too large.",
				);
			}
			chunks.push(result.value);
		}
	} catch (error) {
		if (error instanceof SecretEffectsClientError) throw error;
		throw clientError(
			"RESPONSE",
			"The Secret Effects response could not be read.",
		);
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
		return Schema.decodeUnknownSync(SealedBundle)(parsed);
	} catch {
		throw clientError("RESPONSE", "The Secret Effects response is invalid.");
	}
}

/**
 * Reads one response chunk within the request deadline.
 *
 * @param reader - The response body reader.
 * @param signal - The deadline signal shared with the request.
 * @returns The next stream read result.
 * @throws {@link Error} When the deadline expires or the stream fails.
 */
async function readChunk(
	reader: ReadableStreamDefaultReader<Uint8Array>,
	signal: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
	if (signal.aborted) throw signal.reason;
	return new Promise(
		/**
		 * Starts one abort-aware response body read.
		 *
		 * @param resolve - The callback that receives a stream read result.
		 * @param reject - The callback that receives a stream or deadline failure.
		 */
		(resolve, reject) => {
			/**
			 * Cancels the active body read after the deadline expires.
			 */
			function abort() {
				void reader.cancel(signal.reason).catch(() => undefined);
				reject(signal.reason);
			}
			signal.addEventListener("abort", abort, { once: true });
			reader
				.read()
				.then(resolve, reject)
				.finally(
					/**
					 * Removes the deadline listener after the body read settles.
					 */
					() => {
						signal.removeEventListener("abort", abort);
					},
				);
		},
	);
}

/**
 * Rejects ambiguous ownership for each Secret Effects value.
 *
 * @param config - The repository configuration that identifies remote secrets.
 * @param runtimeEnv - The normalized local runtime values.
 * @throws {@link SecretEffectsClientError} When a local value conflicts with a remote secret.
 */
function rejectSourceConflicts(
	config: SecretEffectsConfig,
	runtimeEnv: RuntimeEnv,
): void {
	for (const name of Object.keys(config.secretDefinitions)) {
		const value = runtimeEnv[name];
		if (value !== undefined && value !== "") {
			throw clientError(
				"SOURCE_CONFLICT",
				`${name} exists in both the runtime and Secret Effects sources.`,
			);
		}
	}
}

/**
 * Converts T3 validation issues into a value-free client error.
 *
 * @param issues - The Standard Schema validation issues.
 * @throws {@link SecretEffectsClientError} Always, with only invalid variable names.
 */
function throwValidationError(
	issues: readonly StandardSchemaV1.Issue[],
): never {
	const names = [
		...new Set(
			issues
				.map(issuePathKey)
				.filter((name): name is PropertyKey => name !== undefined)
				.map(String),
		),
	].sort();
	const suffix = names.length === 0 ? "" : `: ${names.join(", ")}`;
	throw clientError("VALIDATION", `Environment validation failed${suffix}.`);
}

/**
 * Returns the first property key from one Standard Schema issue path.
 *
 * @param issue - The validation issue that contains the optional path.
 * @returns The first primitive key or structured path-segment key.
 */
function issuePathKey(issue: StandardSchemaV1.Issue): PropertyKey | undefined {
	const segment = issue.path?.[0];
	return typeof segment === "object" ? segment.key : segment;
}

/**
 * Encodes one validated machine name for a request path.
 *
 * @param value - The machine name to encode.
 * @returns The encoded path segment.
 */
function formatPathSegment(value: string): string {
	return encodeURIComponent(value);
}

/**
 * Creates one typed and value-free public client error.
 *
 * @param code - The stable error category.
 * @param message - The safe public error message.
 * @returns The typed client error.
 */
function clientError(
	code: SecretEffectsClientErrorCode,
	message: string,
): SecretEffectsClientError {
	return new SecretEffectsClientError({ code, message });
}
