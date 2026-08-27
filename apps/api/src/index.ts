/**
 * Serves the Secret Effects Worker API and queue consumer.
 *
 * @remarks
 * Responsibility: Owns request routing, authentication, access checks, control records, bundle coordination, and cache invalidation.
 *
 * Boundary: Accepts encrypted bundles and signed requests. It delegates cryptography, project serialization, and audit storage.
 */
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import * as Sentry from "@sentry/cloudflare";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	encodeCredentialPayload,
	hexToBytes,
	requestSigningMessage,
	signPayload,
	verifyPayload,
} from "@secret-effects/crypto";
import {
	DEFAULT_ENVIRONMENTS,
	CredentialIssueRequest,
	EnvironmentCreateRequest,
	assertMachineName,
	bundleObjectKey,
	canonicalJson,
	decodeCredentialIssueRequest,
	decodeCredentialRevokeRequest,
	decodeProjectCreateRequest,
	decodePublishBundleRequest,
	decodePurgeMessage,
	decodeSchemaManifestRequest,
	environmentCacheTag,
	type CredentialPayload,
	type CredentialType,
	type PurgeMessage,
} from "@secret-effects/protocol";
import type { ApiEnv } from "../../../alchemy.run.ts";
import { AuditLog } from "./audit-log.ts";
import { ProjectState } from "./project-state.ts";

const encoder = new TextEncoder();
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const AUTH_WINDOW_MS = 5 * 60 * 1000;
const FUTURE_SKEW_MS = 30 * 1000;
const NONCE_RETENTION_MS = 2 * AUTH_WINDOW_MS;
const BOOTSTRAP_RATE_LIMIT = 5;
const BOOTSTRAP_RATE_WINDOW_MS = 60 * 1000;
const MAX_SCHEMAS_PER_PROJECT = 100;

class ApiError extends Data.TaggedError("ApiError")<{
	status: number;
	code: string;
	message: string;
}> {}

interface AuthenticatedCredential {
	identifier: string;
	type: CredentialType;
	project: string | null;
	environment: string | null;
	authPublicKey: string;
}

interface CredentialRow {
	identifier: string;
	type: CredentialType;
	project: string | null;
	environment: string | null;
	auth_public_key: string;
	status: string;
	expires_at: number | null;
}

export { AuditLog, ProjectState };

const handler = {
	/**
	 * Handles one Secret Effects Worker request.
	 *
	 * @param request - The inbound HTTP request.
	 * @param env - The Cloudflare resource bindings for the service.
	 * @param ctx - The Cloudflare execution or Durable Object context.
	 * @returns The HTTP response for the operation.
	 */
	async fetch(request, env, ctx): Promise<Response> {
		return Effect.runPromise(
			handleRequest(request, env, ctx).pipe(
				Effect.catch((error) => Effect.succeed(errorResponse(error))),
			),
		);
	},

	/**
	 * Processes encrypted bundle cache purge messages.
	 *
	 * @param batch - The delivered cache purge message batch.
	 * @param _env - The unused Worker bindings supplied by the queue runtime.
	 * @param ctx - The Cloudflare execution or Durable Object context.
	 * @returns A promise that completes after the operation finishes.
	 */
	async queue(batch, _env, ctx): Promise<void> {
		for (const message of batch.messages) {
			try {
				const body = decodePurgeMessage(message.body);
				if (ctx.cache === undefined) {
					message.retry({ delaySeconds: 30 });
					continue;
				}
				const result = await ctx.cache.purge({ tags: [body.tag] });
				if (!result.success) {
					message.retry({ delaySeconds: 30 });
					continue;
				}
				message.ack();
			} catch (cause) {
				Sentry.captureException(cause);
				message.retry({ delaySeconds: 30 });
			}
		}
	},
} satisfies ExportedHandler<ApiEnv, PurgeMessage>;

export default Sentry.withSentry<ApiEnv, PurgeMessage>(
	(env) => ({
		beforeSend: scrubSentryEvent,
		dataCollection: {
			cookies: false,
			databaseQueryData: false,
			httpBodies: [],
			httpHeaders: { request: false, response: false },
			stackFrameVariables: false,
			urlQueryParams: false,
			userInfo: false,
		},
		dsn: env.SENTRY_DSN,
		enabled: env.SENTRY_DSN !== undefined,
		maxBreadcrumbs: 0,
		sendDefaultPii: false,
		tracesSampleRate: 0,
	}),
	handler,
);

/**
 * Removes request and transaction metadata from a Sentry error event.
 *
 * @param event - The error event to sanitize.
 * @returns The error event without request-specific metadata.
 */
function scrubSentryEvent(event: Sentry.ErrorEvent): Sentry.ErrorEvent {
	const { request: _request, transaction: _transaction, ...sanitized } = event;
	return sanitized;
}

/**
 * Wraps API request execution in the typed application effect.
 *
 * @param request - The inbound HTTP request.
 * @param env - The Cloudflare resource bindings for the service.
 * @param ctx - The Cloudflare execution or Durable Object context.
 * @returns The typed effect that produces the HTTP response.
 */
function handleRequest(
	request: Request,
	env: ApiEnv,
	ctx: ExecutionContext,
): Effect.Effect<Response, ApiError> {
	return Effect.tryPromise({
		try: async () => route(request, env, ctx),
		catch: mapApiError,
	});
}

/**
 * Converts a request failure into an API error and reports unexpected causes.
 *
 * @param cause - The request failure to classify.
 * @returns The public API error for the failure.
 */
function mapApiError(cause: unknown): ApiError {
	if (cause instanceof ApiError) {
		return cause;
	}
	if (cause instanceof Schema.SchemaError) {
		return new ApiError({
			status: 400,
			code: "invalid_request",
			message: "The request does not match the API schema.",
		});
	}
	Sentry.captureException(cause);
	return new ApiError({
		status: 500,
		code: "internal_error",
		message: "The request failed.",
	});
}

/**
 * Routes one authenticated or public API request.
 *
 * @param request - The inbound HTTP request.
 * @param env - The Cloudflare resource bindings for the service.
 * @param ctx - The Cloudflare execution or Durable Object context.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function route(
	request: Request,
	env: ApiEnv,
	ctx: ExecutionContext,
): Promise<Response> {
	const url = new URL(request.url);
	if (request.method === "GET" && url.pathname === "/health") {
		return json({
			status: "ok",
			service: "secret-effects",
			version: 1,
			release: env.SENTRY_RELEASE,
		});
	}
	if (
		request.method === "GET" &&
		url.pathname === "/.well-known/secret-effects"
	) {
		return json({
			version: 1,
			issuer: env.ISSUER_ID,
			issuerPublicKey: bytesToHex(
				ed25519.getPublicKey(hexToBytes(env.ISSUER_PRIVATE_KEY)),
			),
			credentialPrefix: "secret_effects_v1",
		});
	}

	const body = await readBody(request);
	if (request.method === "POST" && url.pathname === "/v1/bootstrap") {
		return bootstrap(request, env, body);
	}

	const actor = await authenticate(request, env, body);

	if (request.method === "POST" && url.pathname === "/v1/projects") {
		allow(actor, ["global", "cicd"]);
		return createProject(env, actor, body);
	}
	if (request.method === "GET" && url.pathname === "/v1/projects") {
		allow(actor, ["global", "cicd", "agent"]);
		return listProjects(env);
	}
	if (request.method === "GET" && url.pathname === "/v1/credentials") {
		allow(actor, ["global", "cicd", "project", "agent"]);
		return listCredentials(env, actor);
	}
	if (request.method === "POST" && url.pathname === "/v1/credentials") {
		return issueCredential(env, actor, body);
	}
	const revokePath = /^\/v1\/credentials\/([a-f0-9]{32})\/revoke$/.exec(
		url.pathname,
	);
	if (request.method === "POST" && revokePath !== null) {
		return revokeCredential(env, actor, revokePath[1] as string, body);
	}
	if (request.method === "GET" && url.pathname === "/v1/audit") {
		allow(actor, ["global", "cicd", "agent"]);
		return json({ events: await audit(env).list(null) });
	}

	const projectEnvironmentsPath =
		/^\/v1\/projects\/([a-z][a-z0-9]*)\/environments$/.exec(url.pathname);
	if (request.method === "GET" && projectEnvironmentsPath !== null) {
		const project = projectEnvironmentsPath[1] as string;
		assertScope(actor, project, null);
		allow(actor, ["global", "cicd", "project", "agent"]);
		return listEnvironments(env, project);
	}

	const schemasPath = /^\/v1\/projects\/([a-z][a-z0-9]*)\/schemas$/.exec(
		url.pathname,
	);
	if (schemasPath !== null) {
		const project = schemasPath[1] as string;
		assertScope(actor, project, null);
		if (request.method === "POST") {
			allow(actor, ["global", "cicd", "project"]);
			return registerSchema(env, actor, project, body);
		}
		if (request.method === "GET") {
			allow(actor, ["global", "cicd", "project", "agent"]);
			return listSchemas(env, project);
		}
	}

	const environmentPath =
		/^\/v1\/projects\/([a-z][a-z0-9]*)\/environments\/([a-z][a-z0-9]*)(?:\/(bundle|bundles|cache))?$/.exec(
			url.pathname,
		);
	if (environmentPath !== null) {
		const project = environmentPath[1] as string;
		const environment = environmentPath[2] as string;
		const operation = environmentPath[3];
		assertScope(actor, project, environment);
		if (request.method === "POST" && operation === undefined) {
			allow(actor, ["global", "cicd", "project", "agent"]);
			return createEnvironment(env, actor, project, environment, body);
		}
		if (request.method === "POST" && operation === "bundles") {
			allow(actor, ["project"]);
			return publishBundle(env, ctx, actor, project, environment, body);
		}
		if (request.method === "GET" && operation === "bundle") {
			allow(actor, ["project", "environment"]);
			return readBundle(env, actor, project, environment);
		}
		if (request.method === "POST" && operation === "cache") {
			allow(actor, ["global", "cicd", "project"]);
			return purgeEnvironment(env, ctx, project, environment);
		}
	}

	const auditPath = /^\/v1\/projects\/([a-z][a-z0-9]*)\/audit$/.exec(
		url.pathname,
	);
	if (request.method === "GET" && auditPath !== null) {
		const project = auditPath[1] as string;
		assertScope(actor, project, null);
		allow(actor, ["global", "cicd", "project", "agent"]);
		const [control, publications] = await Promise.all([
			audit(env).list(project),
			env.PROJECTS.getByName(project).audit(),
		]);
		return json({ control, publications });
	}

	throw new ApiError({
		status: 404,
		code: "not_found",
		message: "The endpoint does not exist.",
	});
}

/**
 * Issues the first Global credential after global admin token authentication.
 *
 * @param request - The inbound HTTP request.
 * @param env - The Cloudflare resource bindings for the service.
 * @param body - The raw credential issue request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function bootstrap(
	request: Request,
	env: ApiEnv,
	body: Uint8Array,
): Promise<Response> {
	await enforceBootstrapRateLimit(env);
	const authorization = request.headers.get("authorization");
	if (
		authorization === null ||
		!timingSafeEqualStrings(authorization, `Bearer ${env.GLOBAL_ADMIN_TOKEN}`)
	) {
		throw new ApiError({
			status: 401,
			code: "unauthorized",
			message: "The global admin token is invalid.",
		});
	}
	const existing = await env.CATALOG.prepare(
		"SELECT identifier FROM credentials WHERE type = 'global' AND status = 'active' LIMIT 1",
	).first<{ identifier: string }>();
	if (existing !== null) {
		throw new ApiError({
			status: 409,
			code: "already_bootstrapped",
			message: "The service already has a Global credential.",
		});
	}
	const issue = decodeCredentialIssueRequest(parseJson(body));
	if (
		issue.type !== "global" ||
		issue.project !== null ||
		issue.environment !== null
	) {
		throw new ApiError({
			status: 400,
			code: "invalid_bootstrap",
			message: "Bootstrap can issue only a Global credential.",
		});
	}
	await validateCredentialIssue(env, issue);
	return persistIssuedCredential(env, issue, "bootstrap");
}

/**
 * Counts bootstrap attempts per fixed window and rejects the excess.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @returns A promise that completes when the attempt is within the limit.
 * @throws {@link ApiError} When the attempt count for the current window exceeds the limit.
 */
async function enforceBootstrapRateLimit(env: ApiEnv): Promise<void> {
	const now = Date.now();
	const cutoff = now - BOOTSTRAP_RATE_WINDOW_MS;
	const row = await env.CATALOG.prepare(
		`INSERT INTO rate_limits(key, window_start, count) VALUES ('bootstrap', ?, 1)
		 ON CONFLICT(key) DO UPDATE SET
		 count = CASE WHEN window_start < ? THEN 1 ELSE count + 1 END,
		 window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END
		 RETURNING count`,
	)
		.bind(now, cutoff, cutoff, now)
		.first<{ count: number }>();
	if ((row?.count ?? 0) > BOOTSTRAP_RATE_LIMIT) {
		throw new ApiError({
			status: 429,
			code: "rate_limited",
			message: "Too many bootstrap attempts. Retry later.",
		});
	}
}

/**
 * Authenticates a signed request and rejects stale, future-dated, or replayed nonces.
 *
 * @param request - The inbound HTTP request.
 * @param env - The Cloudflare resource bindings for the service.
 * @param body - The exact request body bytes covered by the signature.
 * @returns The authenticated active credential and its service scope.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function authenticate(
	request: Request,
	env: ApiEnv,
	body: Uint8Array,
): Promise<AuthenticatedCredential> {
	const identifier = requiredHeader(request, "x-secret-effects-id");
	const timestamp = requiredHeader(request, "x-secret-effects-time");
	const nonce = requiredHeader(request, "x-secret-effects-nonce");
	const signature = requiredHeader(request, "x-secret-effects-signature");
	const timestampNumber = Number(timestamp);
	const now = Date.now();
	if (
		!Number.isSafeInteger(timestampNumber) ||
		timestampNumber - now > FUTURE_SKEW_MS ||
		now - timestampNumber > AUTH_WINDOW_MS
	) {
		throw new ApiError({
			status: 401,
			code: "expired_request",
			message: "The request timestamp is outside the accepted window.",
		});
	}
	if (!/^[0-9a-f]{32}$/.test(nonce)) {
		throw new ApiError({
			status: 401,
			code: "invalid_nonce",
			message: "The request nonce is invalid.",
		});
	}
	const row = await env.CATALOG.prepare(
		"SELECT identifier, type, project, environment, auth_public_key, status, expires_at FROM credentials WHERE identifier = ?",
	)
		.bind(identifier)
		.first<CredentialRow>();
	if (
		row === null ||
		row.status !== "active" ||
		(row.expires_at !== null && row.expires_at <= Date.now())
	) {
		throw new ApiError({
			status: 401,
			code: "inactive_credential",
			message: "The credential is not active.",
		});
	}
	const url = new URL(request.url);
	const message = await requestSigningMessage(
		request.method,
		url.pathname + url.search,
		timestamp,
		nonce,
		body,
	);
	if (
		!verifyPayload(
			message,
			base64UrlToBytes(signature),
			hexToBytes(row.auth_public_key),
		)
	) {
		throw new ApiError({
			status: 401,
			code: "invalid_signature",
			message: "The request signature is invalid.",
		});
	}
	try {
		await env.CATALOG.batch([
			env.CATALOG.prepare(
				"DELETE FROM request_nonces WHERE expires_at < ?",
			).bind(Date.now()),
			env.CATALOG.prepare(
				"INSERT INTO request_nonces(credential_id, nonce, expires_at) VALUES (?, ?, ?)",
			).bind(identifier, nonce, Date.now() + NONCE_RETENTION_MS),
		]);
	} catch {
		throw new ApiError({
			status: 409,
			code: "replayed_request",
			message: "The request nonce was already used.",
		});
	}
	return {
		identifier: row.identifier,
		type: row.type,
		project: row.project,
		environment: row.environment,
		authPublicKey: row.auth_public_key,
	};
}

/**
 * Creates one project with its default environments.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param body - The raw project creation request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function createProject(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	body: Uint8Array,
): Promise<Response> {
	const input = decodeProjectCreateRequest(parseJson(body));
	assertMachineNameApi(input.name, "The project name");
	const now = Date.now();
	try {
		await env.CATALOG.batch([
			env.CATALOG.prepare(
				"INSERT INTO projects(name, display_name, created_at, created_by) VALUES (?, ?, ?, ?)",
			).bind(input.name, input.displayName, now, actor.identifier),
			...DEFAULT_ENVIRONMENTS.map((name) =>
				env.CATALOG.prepare(
					"INSERT INTO environments(project, name, is_default, created_at, created_by) VALUES (?, ?, 1, ?, ?)",
				).bind(input.name, name, now, actor.identifier),
			),
		]);
	} catch {
		throw new ApiError({
			status: 409,
			code: "project_exists",
			message: "The project already exists.",
		});
	}
	await env.PROJECTS.getByName(input.name).initialize();
	await appendAudit(env, actor, {
		action: "project.create",
		project: input.name,
		environment: null,
		subject: input.name,
		details: { displayName: input.displayName },
	});
	return json({ project: input.name, environments: DEFAULT_ENVIRONMENTS }, 201);
}

/**
 * Lists all registered projects.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @returns The HTTP response for the operation.
 */
async function listProjects(env: ApiEnv): Promise<Response> {
	const result = await env.CATALOG.prepare(
		"SELECT name, display_name AS displayName, created_at AS createdAt FROM projects ORDER BY name",
	).all();
	return json({ projects: result.results });
}

/**
 * Lists environments for the selected project.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param project - The machine name of the target project.
 * @returns The HTTP response for the operation.
 */
async function listEnvironments(
	env: ApiEnv,
	project: string,
): Promise<Response> {
	const result = await env.CATALOG.prepare(
		"SELECT name, is_default AS isDefault, created_at AS createdAt FROM environments WHERE project = ? ORDER BY name",
	)
		.bind(project)
		.all();
	return json({ project, environments: result.results });
}

/**
 * Creates one named environment within a project.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @param body - The optional environment creation request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function createEnvironment(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	project: string,
	environment: string,
	body: Uint8Array,
): Promise<Response> {
	const input =
		body.byteLength === 0
			? { name: environment }
			: Schema.decodeUnknownSync(EnvironmentCreateRequest)(parseJson(body));
	if (input.name !== environment) {
		throw new ApiError({
			status: 400,
			code: "environment_mismatch",
			message: "The environment names do not match.",
		});
	}
	assertMachineNameApi(environment, "The environment name");
	try {
		await env.CATALOG.prepare(
			"INSERT INTO environments(project, name, is_default, created_at, created_by) VALUES (?, ?, 0, ?, ?)",
		)
			.bind(project, environment, Date.now(), actor.identifier)
			.run();
	} catch {
		throw new ApiError({
			status: 409,
			code: "environment_exists",
			message: "The environment already exists.",
		});
	}
	await env.PROJECTS.getByName(project).createEnvironment(environment);
	await appendAudit(env, actor, {
		action: "environment.create",
		project,
		environment,
		subject: environment,
		details: {},
	});
	return json({ project, environment }, 201);
}

/**
 * Authorizes and issues a subordinate credential.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param body - The raw credential issue request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function issueCredential(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	body: Uint8Array,
): Promise<Response> {
	const issue = decodeCredentialIssueRequest(parseJson(body));
	await validateCredentialIssue(env, issue);
	const allowed =
		actor.type === "global"
			? ["cicd", "project", "agent", "environment"]
			: actor.type === "cicd"
				? ["project", "agent", "environment"]
				: actor.type === "project"
					? ["environment"]
					: [];
	if (!allowed.includes(issue.type)) {
		throw new ApiError({
			status: 403,
			code: "forbidden",
			message: "The credential cannot issue the requested type.",
		});
	}
	if (actor.project !== null && actor.project !== issue.project) {
		throw new ApiError({
			status: 403,
			code: "scope_mismatch",
			message: "The requested project is outside the credential scope.",
		});
	}
	return persistIssuedCredential(env, issue, actor.identifier);
}

/**
 * Signs and persists one authorized credential, then records its audit event.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param issue - The credential fields that the issuer must validate and sign.
 * @param issuedBy - The identity that authorized credential issuance.
 * @returns The HTTP response for the operation.
 */
async function persistIssuedCredential(
	env: ApiEnv,
	issue: typeof CredentialIssueRequest.Type,
	issuedBy: string,
): Promise<Response> {
	const identifier = crypto.randomUUID().replaceAll("-", "");
	const now = Date.now();
	const issuerPrivateKey = hexToBytes(env.ISSUER_PRIVATE_KEY);
	const payload: CredentialPayload = {
		version: 1,
		api: env.API_ORIGIN,
		issuer: env.ISSUER_ID,
		issuerPublicKey: bytesToHex(ed25519.getPublicKey(issuerPrivateKey)),
		type: issue.type,
		project: issue.project,
		environment: issue.environment,
		identifier,
		authPublicKey: issue.authPublicKey,
		decryptPublicKey: issue.decryptPublicKey,
		issuedAt: now,
		notBefore: now - 30_000,
		expiresAt: issue.expiresAt,
	};
	const payloadBytes = await encodeCredentialPayload(payload);
	const signature = signPayload(payloadBytes, issuerPrivateKey);
	try {
		await env.CATALOG.prepare(
			`INSERT INTO credentials(identifier, type, project, environment, auth_public_key, decrypt_public_key, status, issued_at, expires_at, issued_by)
			 VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		)
			.bind(
				identifier,
				issue.type,
				issue.project,
				issue.environment,
				issue.authPublicKey,
				issue.decryptPublicKey,
				now,
				issue.expiresAt,
				issuedBy,
			)
			.run();
	} catch (cause) {
		if (
			issue.type === "global" &&
			issuedBy === "bootstrap" &&
			cause instanceof Error &&
			cause.message.includes("UNIQUE constraint failed: credentials.type")
		) {
			throw new ApiError({
				status: 409,
				code: "already_bootstrapped",
				message: "The service already has a Global credential.",
			});
		}
		throw cause;
	}
	await appendAudit(env, issuedBy, {
		action: "credential.issue.authorized",
		project: issue.project,
		environment: issue.environment,
		subject: identifier,
		details: { type: issue.type, issuedBy, expiresAt: issue.expiresAt },
	});
	return json(
		{
			payload: bytesToBase64Url(payloadBytes),
			signature: bytesToBase64Url(signature),
		},
		201,
	);
}

/**
 * Lists credentials visible to the authenticated scope.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @returns The HTTP response for the operation.
 */
async function listCredentials(
	env: ApiEnv,
	actor: AuthenticatedCredential,
): Promise<Response> {
	const query =
		actor.project === null
			? env.CATALOG.prepare(
					`SELECT identifier, type, project, environment, status, issued_at AS issuedAt,
					 expires_at AS expiresAt, issued_by AS issuedBy, revoked_at AS revokedAt
					 FROM credentials ORDER BY issued_at DESC`,
				)
			: env.CATALOG.prepare(
					`SELECT identifier, type, project, environment, status, issued_at AS issuedAt,
					 expires_at AS expiresAt, issued_by AS issuedBy, revoked_at AS revokedAt
					 FROM credentials WHERE project = ? ORDER BY issued_at DESC`,
				).bind(actor.project);
	const result = await query.all();
	return json({ credentials: result.results });
}

/**
 * Revokes one active credential.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param identifier - The stable credential or recipient identifier.
 * @param body - The raw credential revocation request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function revokeCredential(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	identifier: string,
	body: Uint8Array,
): Promise<Response> {
	const input = decodeCredentialRevokeRequest(parseJson(body));
	if (input.reason.trim().length < 3 || input.reason.length > 500) {
		throw new ApiError({
			status: 400,
			code: "invalid_reason",
			message: "The revocation reason must contain 3 to 500 characters.",
		});
	}
	const target = await env.CATALOG.prepare(
		"SELECT identifier, type, project, environment, auth_public_key, status, expires_at FROM credentials WHERE identifier = ?",
	)
		.bind(identifier)
		.first<CredentialRow>();
	if (target === null) {
		throw new ApiError({
			status: 404,
			code: "credential_missing",
			message: "The credential does not exist.",
		});
	}
	const allowed =
		actor.type === "global"
			? ["global", "cicd", "project", "agent", "environment"]
			: actor.type === "cicd"
				? ["project", "agent", "environment"]
				: actor.type === "project"
					? ["environment"]
					: [];
	if (!allowed.includes(target.type)) {
		throw new ApiError({
			status: 403,
			code: "forbidden",
			message: "The credential cannot revoke the selected credential.",
		});
	}
	if (actor.project !== null && actor.project !== target.project) {
		throw new ApiError({
			status: 403,
			code: "scope_mismatch",
			message: "The selected credential is outside the project scope.",
		});
	}
	const now = Date.now();
	const result = await env.CATALOG.prepare(
		"UPDATE credentials SET status = 'revoked', revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE identifier = ? AND status = 'active'",
	)
		.bind(now, actor.identifier, input.reason.trim(), identifier)
		.run();
	if (result.meta.changes === 0) {
		throw new ApiError({
			status: 409,
			code: "credential_inactive",
			message: "The credential is already inactive.",
		});
	}
	await appendAudit(env, actor, {
		action: "credential.revoke",
		project: target.project,
		environment: target.environment,
		subject: identifier,
		details: { reason: input.reason.trim(), targetType: target.type },
	});
	return json({ identifier, status: "revoked", revokedAt: now });
}

/**
 * Validates and registers one immutable schema manifest.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param project - The machine name of the target project.
 * @param body - The raw schema manifest request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function registerSchema(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	project: string,
	body: Uint8Array,
): Promise<Response> {
	const input = decodeSchemaManifestRequest(parseJson(body));
	if (
		typeof input.manifest !== "object" ||
		input.manifest === null ||
		!("version" in input.manifest) ||
		input.manifest.version !== 1 ||
		!("project" in input.manifest) ||
		input.manifest.project !== project
	) {
		throw new ApiError({
			status: 400,
			code: "schema_scope_mismatch",
			message: "The schema manifest does not match the project.",
		});
	}
	if (!/^[0-9a-f]{64}$/.test(input.digest)) {
		throw new ApiError({
			status: 400,
			code: "invalid_schema_digest",
			message: "The schema digest must be a SHA-256 hexadecimal value.",
		});
	}
	const manifestText = canonicalJson(input.manifest);
	const computed = bytesToHex(sha256(encoder.encode(manifestText)));
	if (computed !== input.digest) {
		throw new ApiError({
			status: 400,
			code: "schema_digest_mismatch",
			message: "The schema manifest does not match its digest.",
		});
	}
	const existing = await env.CATALOG.prepare(
		"SELECT manifest FROM schema_manifests WHERE project = ? AND digest = ?",
	)
		.bind(project, input.digest)
		.first<{ manifest: string }>();
	if (existing !== null && existing.manifest !== manifestText) {
		throw new ApiError({
			status: 409,
			code: "schema_digest_collision",
			message: "The schema digest is already assigned to another manifest.",
		});
	}
	if (existing === null) {
		const count = await env.CATALOG.prepare(
			"SELECT COUNT(*) AS count FROM schema_manifests WHERE project = ?",
		)
			.bind(project)
			.first<{ count: number }>();
		if ((count?.count ?? 0) >= MAX_SCHEMAS_PER_PROJECT) {
			throw new ApiError({
				status: 409,
				code: "schema_limit_reached",
				message: "The project reached its schema manifest limit.",
			});
		}
		await env.CATALOG.prepare(
			"INSERT INTO schema_manifests(project, digest, manifest, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
		)
			.bind(project, input.digest, manifestText, Date.now(), actor.identifier)
			.run();
		await appendAudit(env, actor, {
			action: "schema.register",
			project,
			environment: null,
			subject: input.digest,
			details: {},
		});
	}
	return json({ project, digest: input.digest }, existing === null ? 201 : 200);
}

/**
 * Lists registered schema digests for one project.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param project - The machine name of the target project.
 * @returns The HTTP response for the operation.
 */
async function listSchemas(env: ApiEnv, project: string): Promise<Response> {
	const result = await env.CATALOG.prepare(
		"SELECT digest, created_at AS createdAt, created_by AS createdBy FROM schema_manifests WHERE project = ? ORDER BY created_at DESC",
	)
		.bind(project)
		.all();
	return json({ project, schemas: result.results });
}

/**
 * Encrypts and publishes one environment bundle.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param ctx - The Cloudflare execution or Durable Object context.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @param body - The raw encrypted bundle publication request body.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function publishBundle(
	env: ApiEnv,
	ctx: ExecutionContext,
	actor: AuthenticatedCredential,
	project: string,
	environment: string,
	body: Uint8Array,
): Promise<Response> {
	const input = decodePublishBundleRequest(parseJson(body));
	if (
		input.bundle.project !== project ||
		input.bundle.environment !== environment
	) {
		throw new ApiError({
			status: 400,
			code: "bundle_scope_mismatch",
			message: "The bundle scope does not match the request path.",
		});
	}
	if (input.bundle.author !== actor.identifier) {
		throw new ApiError({
			status: 403,
			code: "bundle_author_mismatch",
			message: "The bundle author does not match the request credential.",
		});
	}
	if (
		input.bundle.authorPublicKey !== actor.authPublicKey ||
		input.bundle.serviceSignature !== null
	) {
		throw new ApiError({
			status: 400,
			code: "invalid_bundle_attestation",
			message: "The bundle attestation fields are invalid.",
		});
	}
	const schema = await env.CATALOG.prepare(
		"SELECT digest FROM schema_manifests WHERE project = ? AND digest = ?",
	)
		.bind(project, input.bundle.schemaDigest)
		.first<{ digest: string }>();
	if (schema === null) {
		throw new ApiError({
			status: 409,
			code: "schema_missing",
			message: "Register the repository schema before bundle publication.",
		});
	}
	await validateBundleRecipients(
		env,
		project,
		environment,
		input.bundle.recipients,
	);
	const {
		signature,
		serviceSignature: _serviceSignature,
		...unsigned
	} = input.bundle;
	if (
		!verifyPayload(
			encoder.encode(canonicalJson(unsigned)),
			base64UrlToBytes(signature),
			hexToBytes(actor.authPublicKey),
		)
	) {
		throw new ApiError({
			status: 400,
			code: "invalid_bundle_signature",
			message: "The bundle signature is invalid.",
		});
	}
	const acceptedBundle = {
		...input.bundle,
		serviceSignature: bytesToBase64Url(
			signPayload(
				encoder.encode(canonicalJson(input.bundle)),
				hexToBytes(env.ISSUER_PRIVATE_KEY),
			),
		),
	};
	const objectKey = bundleObjectKey(acceptedBundle);
	const bundleText = JSON.stringify(acceptedBundle);
	const digest = bytesToHex(sha256(encoder.encode(bundleText)));
	let outcome;
	try {
		outcome = await env.PROJECTS.getByName(project).publish({
			environment,
			objectKey,
			bundle: bundleText,
			baseVersion: input.baseVersion,
			contentVersion: acceptedBundle.contentVersion,
			envelopeVersion: acceptedBundle.envelopeVersion,
			idempotencyKey: input.idempotencyKey,
			actor: actor.identifier,
			digest,
			createdAt: input.bundle.createdAt,
		});
	} catch {
		throw new ApiError({
			status: 503,
			code: "publication_unavailable",
			message: "The publication service is temporarily unavailable.",
		});
	}
	if (outcome.status === "conflict") {
		throw new ApiError({
			status: 409,
			code: "publish_conflict",
			message: "The environment changed after the client loaded it.",
		});
	}
	if (outcome.status === "version_reused") {
		throw new ApiError({
			status: 409,
			code: "bundle_version_reused",
			message: "The bundle content version was already published.",
		});
	}
	const result = outcome.result;
	const purge = await purgeCache(
		ctx,
		environmentCacheTag(project, environment),
	);
	if (!purge) {
		await env.PURGE_QUEUE.send({
			project,
			environment,
			tag: environmentCacheTag(project, environment),
			attempt: 1,
		});
	}
	await appendAudit(env, actor, {
		action: "bundle.publish",
		project,
		environment,
		subject: input.bundle.contentVersion,
		details: {
			digest,
			envelopeVersion: input.bundle.envelopeVersion,
			schemaDigest: input.bundle.schemaDigest,
		},
	});
	return json(
		{ ...result, cache: purge ? "purged" : "pending" },
		result.replayed ? 200 : 201,
	);
}

/**
 * Validates that each bundle recipient is an active credential of the target scope.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @param recipients - The recipient records named by the bundle envelope.
 * @returns A promise that completes when every recipient is in scope.
 * @throws {@link ApiError} When a recipient is not an active project or matching environment credential.
 */
async function validateBundleRecipients(
	env: ApiEnv,
	project: string,
	environment: string,
	recipients: readonly { identifier: string }[],
): Promise<void> {
	const rows = await env.CATALOG.prepare(
		`SELECT identifier, type, environment FROM credentials
		 WHERE project = ? AND status = 'active' AND type IN ('project', 'environment')`,
	)
		.bind(project)
		.all<{ identifier: string; type: string; environment: string | null }>();
	const index = new Map(
		rows.results.map((row) => [row.identifier as string, row]),
	);
	for (const recipient of recipients) {
		const row = index.get(recipient.identifier);
		if (
			row === undefined ||
			(row.type === "environment" && row.environment !== environment)
		) {
			throw new ApiError({
				status: 400,
				code: "invalid_bundle_recipient",
				message:
					"The bundle names a recipient outside the active credentials of this environment.",
			});
		}
	}
}

/**
 * Reads one accepted encrypted bundle through the edge cache.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @returns The HTTP response for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function readBundle(
	env: ApiEnv,
	actor: AuthenticatedCredential,
	project: string,
	environment: string,
): Promise<Response> {
	if (actor.type === "environment" && actor.environment !== environment) {
		throw new ApiError({
			status: 403,
			code: "scope_mismatch",
			message: "The credential cannot read this environment.",
		});
	}
	const cacheKey = new Request(
		`https://cache.secret-effects.invalid/${project}/${environment}`,
		{ method: "GET" },
	);
	const cache = (caches as CloudflareCacheStorage).default;
	const cached = await cache.match(cacheKey);
	if (cached !== undefined) {
		return privateBundleResponse(cached.body, cached.headers.get("etag"));
	}
	const current = await env.PROJECTS.getByName(project).current(environment);
	if (current === null) {
		throw new ApiError({
			status: 404,
			code: "bundle_missing",
			message: "The environment has no active bundle.",
		});
	}
	const object = await env.BUNDLES.get(current.objectKey);
	if (object === null) {
		throw new ApiError({
			status: 503,
			code: "bundle_unavailable",
			message: "The active encrypted bundle is unavailable.",
		});
	}
	const cacheResponse = new Response(object.body, {
		headers: {
			"cache-control": "public, max-age=300",
			"cache-tag": environmentCacheTag(project, environment),
			"content-type": "application/vnd.secret-effects.bundle+json",
			etag: current.digest,
		},
	});
	await cache.put(cacheKey, cacheResponse.clone());
	return privateBundleResponse(cacheResponse.body, current.digest);
}

/**
 * Purges or queues cache invalidation for one environment.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param ctx - The Cloudflare execution or Durable Object context.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @returns The HTTP response for the operation.
 */
async function purgeEnvironment(
	env: ApiEnv,
	ctx: ExecutionContext,
	project: string,
	environment: string,
): Promise<Response> {
	const tag = environmentCacheTag(project, environment);
	const purged = await purgeCache(ctx, tag);
	if (!purged) {
		await env.PURGE_QUEUE.send({ project, environment, tag, attempt: 1 });
	}
	return json({ project, environment, cache: purged ? "purged" : "pending" });
}

/**
 * Purges one environment cache tag when cache access exists.
 *
 * @param ctx - The Cloudflare execution or Durable Object context.
 * @param tag - The cache tag to invalidate.
 * @returns True when the cache purge succeeds.
 */
async function purgeCache(
	ctx: ExecutionContext,
	tag: string,
): Promise<boolean> {
	if (ctx.cache === undefined) {
		return false;
	}
	try {
		return (await ctx.cache.purge({ tags: [tag] })).success;
	} catch {
		return false;
	}
}

/**
 * Validates credential keys, scope shape, expiration, and referenced resources.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param issue - The credential fields that the issuer must validate and sign.
 * @returns A promise that completes after the operation finishes.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function validateCredentialIssue(
	env: ApiEnv,
	issue: typeof CredentialIssueRequest.Type,
): Promise<void> {
	if (!/^[0-9a-f]{64}$/.test(issue.authPublicKey)) {
		throw new ApiError({
			status: 400,
			code: "invalid_authentication_key",
			message: "The authentication public key is invalid.",
		});
	}
	const hasDecryptionKey = issue.decryptPublicKey !== null;
	if (
		hasDecryptionKey &&
		!/^[0-9a-f]{64}$/.test(issue.decryptPublicKey as string)
	) {
		throw new ApiError({
			status: 400,
			code: "invalid_decryption_key",
			message: "The decryption public key is invalid.",
		});
	}
	const validShape =
		(issue.type === "global" &&
			issue.project === null &&
			issue.environment === null &&
			!hasDecryptionKey) ||
		((issue.type === "cicd" || issue.type === "agent") &&
			issue.project === null &&
			issue.environment === null &&
			!hasDecryptionKey) ||
		(issue.type === "project" &&
			issue.project !== null &&
			issue.environment === null &&
			hasDecryptionKey) ||
		(issue.type === "environment" &&
			issue.project !== null &&
			issue.environment !== null &&
			hasDecryptionKey);
	if (!validShape) {
		throw new ApiError({
			status: 400,
			code: "invalid_credential_scope",
			message: "The credential type and scope do not match.",
		});
	}
	if (issue.expiresAt !== null && issue.expiresAt <= Date.now()) {
		throw new ApiError({
			status: 400,
			code: "invalid_expiration",
			message: "The credential expiration must be in the future.",
		});
	}
	if (issue.project !== null) {
		assertMachineNameApi(issue.project, "The project name");
		const project = await env.CATALOG.prepare(
			"SELECT name FROM projects WHERE name = ?",
		)
			.bind(issue.project)
			.first();
		if (project === null) {
			throw new ApiError({
				status: 404,
				code: "project_missing",
				message: "The credential project does not exist.",
			});
		}
	}
	if (issue.environment !== null && issue.project !== null) {
		assertMachineNameApi(issue.environment, "The environment name");
		const environment = await env.CATALOG.prepare(
			"SELECT name FROM environments WHERE project = ? AND name = ?",
		)
			.bind(issue.project, issue.environment)
			.first();
		if (environment === null) {
			throw new ApiError({
				status: 404,
				code: "environment_missing",
				message: "The credential environment does not exist.",
			});
		}
	}
}

/**
 * Digests audit details and appends one global control event.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param input - The validated operation data at this boundary.
 * @returns A promise that completes after the operation finishes.
 */
async function appendAudit(
	env: ApiEnv,
	actor: AuthenticatedCredential | string,
	input: {
		action: string;
		project: string | null;
		environment: string | null;
		subject: string | null;
		details: unknown;
	},
): Promise<void> {
	const detailsDigest = bytesToHex(
		sha256(encoder.encode(canonicalJson(input.details))),
	);
	await audit(env).append({
		eventId: crypto.randomUUID(),
		actor: typeof actor === "string" ? actor : actor.identifier,
		action: input.action,
		project: input.project,
		environment: input.environment,
		subject: input.subject,
		detailsDigest,
		createdAt: Date.now(),
	});
}

/**
 * Gets the global audit Durable Object stub.
 *
 * @param env - The Cloudflare resource bindings for the service.
 * @returns The global audit object stub.
 */
function audit(env: ApiEnv): DurableObjectStub<AuditLog> {
	return env.AUDIT.getByName("global");
}

/**
 * Converts an invalid machine name into an API error.
 *
 * @param value - The machine name to validate for an API request.
 * @param label - The human-readable name for validation errors.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
function assertMachineNameApi(value: string, label: string): void {
	try {
		assertMachineName(value, label);
	} catch {
		throw new ApiError({
			status: 400,
			code: "invalid_name",
			message: `${label} is invalid.`,
		});
	}
}

/**
 * Rejects a credential type outside the permitted set.
 *
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param types - The credential types permitted for the operation.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
function allow(
	actor: AuthenticatedCredential,
	types: readonly CredentialType[],
): void {
	if (!types.includes(actor.type)) {
		throw new ApiError({
			status: 403,
			code: "forbidden",
			message: "The credential cannot perform this operation.",
		});
	}
}

/**
 * Rejects a resource scope outside the authenticated credential scope.
 *
 * @param actor - The authenticated credential or issuer identity that authorizes the operation.
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
function assertScope(
	actor: AuthenticatedCredential,
	project: string,
	environment: string | null,
): void {
	if (actor.project !== null && actor.project !== project) {
		throw new ApiError({
			status: 403,
			code: "scope_mismatch",
			message: "The project is outside the credential scope.",
		});
	}
	if (actor.environment !== null && actor.environment !== environment) {
		throw new ApiError({
			status: 403,
			code: "scope_mismatch",
			message: "The environment is outside the credential scope.",
		});
	}
}

/**
 * Reads a request body within the service size limit and cancels oversized streams.
 *
 * @param request - The inbound HTTP request.
 * @returns The bounded request bytes.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
async function readBody(request: Request): Promise<Uint8Array> {
	const length = Number(request.headers.get("content-length") ?? "0");
	if (Number.isFinite(length) && length > MAX_BODY_BYTES) {
		throw new ApiError({
			status: 413,
			code: "body_too_large",
			message: "The request body exceeds the service limit.",
		});
	}
	if (request.body === null) {
		return new Uint8Array(0);
	}
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	while (true) {
		const result = await reader.read();
		if (result.done) {
			break;
		}
		total += result.value.byteLength;
		if (total > MAX_BODY_BYTES) {
			await reader.cancel().catch(() => undefined);
			throw new ApiError({
				status: 413,
				code: "body_too_large",
				message: "The request body exceeds the service limit.",
			});
		}
		chunks.push(result.value);
	}
	return concatChunks(chunks, total);
}

/**
 * Concatenates bounded body chunks into one byte array.
 *
 * @param chunks - The collected body chunks in stream order.
 * @param total - The exact combined byte count of all chunks.
 * @returns The combined request bytes.
 */
function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
	const output = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		output.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return output;
}

/**
 * Parses request bytes as JSON.
 *
 * @param body - The bounded request body bytes to parse.
 * @returns The parsed JSON value.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
function parseJson(body: Uint8Array): unknown {
	try {
		return JSON.parse(new TextDecoder().decode(body));
	} catch {
		throw new ApiError({
			status: 400,
			code: "invalid_json",
			message: "The request body is not valid JSON.",
		});
	}
}

/**
 * Reads one required authentication header.
 *
 * @param request - The inbound HTTP request.
 * @param name - The authentication header name to read.
 * @returns The required header value.
 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
 */
function requiredHeader(request: Request, name: string): string {
	const value = request.headers.get(name);
	if (value === null || value.length === 0) {
		throw new ApiError({
			status: 401,
			code: "missing_authentication",
			message: `The ${name} header is required.`,
		});
	}
	return value;
}

/**
 * Compares fixed-length SHA-256 digests without data-dependent early exit.
 *
 * @param left - The first string in the constant-time comparison.
 * @param right - The second string in the constant-time comparison.
 * @returns True when both strings contain equal bytes.
 */
function timingSafeEqualStrings(left: string, right: string): boolean {
	const leftDigest = sha256(encoder.encode(left));
	const rightDigest = sha256(encoder.encode(right));
	let difference = 0;
	for (let index = 0; index < leftDigest.byteLength; index += 1) {
		difference |=
			(leftDigest[index] as number) ^ (rightDigest[index] as number);
	}
	return difference === 0;
}

/**
 * Creates a private JSON response with security headers.
 *
 * @param value - The response value to serialize as JSON.
 * @param status - The HTTP status for the response.
 * @returns The private JSON response.
 */
function json(value: unknown, status = 200): Response {
	return Response.json(value, {
		status,
		headers: {
			"cache-control": "private, no-store",
			"x-content-type-options": "nosniff",
		},
	});
}

/**
 * Creates a private encrypted bundle response.
 *
 * @param body - The encrypted bundle response body.
 * @param etag - The optional bundle digest for the ETag header.
 * @returns The private encrypted bundle response.
 */
function privateBundleResponse(
	body: BodyInit | null,
	etag: string | null,
): Response {
	const headers = new Headers({
		"cache-control": "private, no-store",
		"content-type": "application/vnd.secret-effects.bundle+json",
		"x-content-type-options": "nosniff",
	});
	if (etag !== null) {
		headers.set("etag", etag);
	}
	return new Response(body, { headers });
}

/**
 * Converts an API error into a private JSON response.
 *
 * @param error - The typed API failure to serialize.
 * @returns The HTTP response for the operation.
 */
function errorResponse(error: ApiError): Response {
	return json(
		{ error: { code: error.code, message: error.message } },
		error.status,
	);
}

interface CloudflareCacheStorage extends CacheStorage {
	readonly default: Cache;
}
