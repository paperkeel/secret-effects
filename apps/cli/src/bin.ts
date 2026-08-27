import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import {
	assembleCredential,
	base64UrlToBytes,
	bytesToHex,
	deriveKeys,
	exportPublicCredential,
	generateMasterKey,
	hexToBytes,
	openBundle,
	parseCredential,
	parsePublicCredential,
	sealBundle,
	signRequest,
} from "@secret-effects/crypto";
import type {
	CredentialIssueRequest,
	CredentialIssueResponse,
	CredentialType,
	PublishBundleRequest,
	SealedBundle,
} from "@secret-effects/protocol";
import { canonicalJson } from "@secret-effects/protocol";

class CliError extends Data.TaggedError("CliError")<{ message: string }> {}

const program = Effect.tryPromise({
	try: () => main(process.argv.slice(2)),
	catch: (cause) =>
		cause instanceof CliError
			? cause
			: new CliError({
					message:
						cause instanceof Error ? cause.message : "The command failed.",
				}),
});

void Effect.runPromise(
	program.pipe(
		Effect.catch((error) =>
			Effect.sync(() => {
				process.stderr.write(`secreteffects: ${error.message}\n`);
				process.exitCode = 1;
			}),
		),
	),
);

async function main(argv: readonly string[]): Promise<void> {
	const [group, command] = argv;
	if (
		group === undefined ||
		group === "help" ||
		group === "--help" ||
		group === "-h"
	) {
		printHelp();
		return;
	}
	if (group === "version" || group === "--version") {
		process.stdout.write("secreteffects 0.1.0\n");
		return;
	}
	if (group === "tui") {
		await import("./tui.tsx");
		return;
	}
	if (group === "bootstrap") {
		await bootstrap(argv.slice(1));
		return;
	}
	if (group === "key" && command === "issue") {
		await issueKey(argv.slice(2));
		return;
	}
	if (group === "key" && command === "list") {
		await listPath("/v1/credentials");
		return;
	}
	if (group === "key" && command === "public") {
		writeJson(exportPublicCredential(await configuredCredential()));
		return;
	}
	if (group === "key" && command === "inspect") {
		writeJson((await configuredCredential()).payload);
		return;
	}
	if (group === "key" && command === "revoke") {
		await revokeKey(argv.slice(2));
		return;
	}
	if (group === "project" && command === "create") {
		await createProject(argv.slice(2));
		return;
	}
	if (group === "project" && command === "list") {
		await listPath("/v1/projects");
		return;
	}
	if (group === "environment" && command === "create") {
		await createEnvironment(argv.slice(2));
		return;
	}
	if (group === "environment" && command === "list") {
		await listEnvironments(argv.slice(2));
		return;
	}
	if (group === "schema" && command === "publish") {
		await publishSchema(argv.slice(2));
		return;
	}
	if (group === "schema" && command === "list") {
		await listSchemas(argv.slice(2));
		return;
	}
	if (group === "bundle" && command === "publish") {
		await publishBundle(argv.slice(2));
		return;
	}
	if (group === "environment" && command === "read") {
		await readEnvironment(argv.slice(2));
		return;
	}
	if (group === "cache" && command === "purge") {
		await purgeCache(argv.slice(2));
		return;
	}
	if (group === "audit" && command === "list") {
		await listAudit(argv.slice(2));
		return;
	}
	throw new CliError({
		message: "The command is not recognized. Run secreteffects help.",
	});
}

async function bootstrap(args: readonly string[]): Promise<void> {
	const api = requiredOption(args, "--api");
	const bootstrapToken = requiredEnv("SECRET_EFFECTS_BOOTSTRAP_TOKEN");
	const masterKey = generateMasterKey();
	const keys = deriveKeys(masterKey);
	const issue: CredentialIssueRequest = {
		type: "global",
		project: null,
		environment: null,
		authPublicKey: bytesToHex(keys.authPublicKey),
		decryptPublicKey: null,
		expiresAt: null,
	};
	const response = await fetch(`${stripTrailingSlash(api)}/v1/bootstrap`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${bootstrapToken}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(issue),
	});
	const issued = await readJson<CredentialIssueResponse>(response);
	writeCredential(
		assembleCredential(
			base64UrlToBytes(issued.payload),
			base64UrlToBytes(issued.signature),
			masterKey,
		),
	);
}

async function issueKey(args: readonly string[]): Promise<void> {
	const parent = await configuredCredential();
	const type = requiredOption(args, "--type") as CredentialType;
	if (!["cicd", "project", "agent", "environment"].includes(type)) {
		throw new CliError({
			message: "--type must be cicd, project, agent, or environment.",
		});
	}
	const project = option(args, "--project") ?? null;
	const environment = option(args, "--environment") ?? null;
	const masterKey = generateMasterKey();
	const keys = deriveKeys(masterKey);
	const issue: CredentialIssueRequest = {
		type,
		project,
		environment,
		authPublicKey: bytesToHex(keys.authPublicKey),
		decryptPublicKey:
			type === "project" || type === "environment"
				? bytesToHex(keys.decryptPublicKey)
				: null,
		expiresAt: null,
	};
	const response = await authenticatedFetch(parent, "/v1/credentials", {
		method: "POST",
		body: JSON.stringify(issue),
	});
	const issued = await readJson<CredentialIssueResponse>(response);
	writeCredential(
		assembleCredential(
			base64UrlToBytes(issued.payload),
			base64UrlToBytes(issued.signature),
			masterKey,
		),
	);
}

async function revokeKey(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const identifier = requiredOption(args, "--id");
	const reason = requiredOption(args, "--reason");
	const response = await authenticatedFetch(
		credential,
		`/v1/credentials/${identifier}/revoke`,
		{ method: "POST", body: JSON.stringify({ reason }) },
	);
	writeJson(await readJson(response));
}

async function createProject(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const name = requiredOption(args, "--name");
	const displayName = option(args, "--display-name") ?? name;
	const response = await authenticatedFetch(credential, "/v1/projects", {
		method: "POST",
		body: JSON.stringify({ name, displayName }),
	});
	process.stdout.write(
		`${JSON.stringify(await readJson(response), null, 2)}\n`,
	);
}

async function createEnvironment(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project = requiredOption(args, "--project");
	const environment = requiredOption(args, "--environment");
	const path = `/v1/projects/${project}/environments/${environment}`;
	const response = await authenticatedFetch(credential, path, {
		method: "POST",
		body: JSON.stringify({ name: environment }),
	});
	process.stdout.write(
		`${JSON.stringify(await readJson(response), null, 2)}\n`,
	);
}

async function listEnvironments(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project =
		option(args, "--project") ?? credential.payload.project ?? undefined;
	if (project === undefined) {
		throw new CliError({ message: "--project is required." });
	}
	await listPath(`/v1/projects/${project}/environments`, credential);
}

async function publishSchema(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project =
		option(args, "--project") ?? credential.payload.project ?? undefined;
	if (project === undefined) {
		throw new CliError({ message: "--project is required." });
	}
	const manifest: unknown = JSON.parse(
		await readTextFile(requiredOption(args, "--manifest")),
	);
	const encoded = new TextEncoder().encode(canonicalJson(manifest));
	const digest = Array.from(
		new Uint8Array(await crypto.subtle.digest("SHA-256", encoded)),
		(byte) => byte.toString(16).padStart(2, "0"),
	).join("");
	const response = await authenticatedFetch(
		credential,
		`/v1/projects/${project}/schemas`,
		{ method: "POST", body: JSON.stringify({ digest, manifest }) },
	);
	writeJson(await readJson(response));
}

async function listSchemas(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project =
		option(args, "--project") ?? credential.payload.project ?? undefined;
	if (project === undefined) {
		throw new CliError({ message: "--project is required." });
	}
	await listPath(`/v1/projects/${project}/schemas`, credential);
}

async function publishBundle(args: readonly string[]): Promise<void> {
	const author = await configuredCredential();
	if (author.payload.type !== "project" || author.payload.project === null) {
		throw new CliError({
			message: "Bundle publication requires a Project credential.",
		});
	}
	const environment = requiredOption(args, "--environment");
	const valuesPath = requiredOption(args, "--values");
	const schemaDigest = requiredOption(args, "--schema-digest");
	const recipientPaths = options(args, "--recipient");
	const recipients = [
		{
			identifier: author.payload.identifier,
			publicKey: author.keys.decryptPublicKey,
		},
	];
	for (const path of recipientPaths) {
		const descriptor = parsePublicDescriptor(
			JSON.parse(await readTextFile(path)),
		);
		const recipient = await parsePublicCredential(descriptor);
		if (
			recipient.payload.project !== author.payload.project ||
			recipient.payload.decryptPublicKey === null ||
			!["project", "environment"].includes(recipient.payload.type)
		) {
			throw new CliError({
				message: `${path} is not a readable credential for this project.`,
			});
		}
		recipients.push({
			identifier: recipient.payload.identifier,
			publicKey: hexToBytes(recipient.payload.decryptPublicKey),
		});
	}
	const rawValues: unknown = JSON.parse(await readTextFile(valuesPath));
	if (
		typeof rawValues !== "object" ||
		rawValues === null ||
		Array.isArray(rawValues)
	) {
		throw new CliError({
			message: "The values file must contain a JSON object.",
		});
	}
	const values = Object.fromEntries(
		Object.entries(rawValues).map(([key, value]) => {
			if (typeof value !== "string") {
				throw new CliError({ message: `${key} must contain a string value.` });
			}
			return [key, value];
		}),
	);
	const bundle = await sealBundle({
		project: author.payload.project,
		environment,
		schemaDigest,
		values,
		recipients,
		author,
	});
	const request: PublishBundleRequest = {
		baseVersion: option(args, "--base-version") ?? null,
		idempotencyKey: option(args, "--idempotency-key") ?? crypto.randomUUID(),
		bundle,
	};
	const path = `/v1/projects/${author.payload.project}/environments/${environment}/bundles`;
	const response = await authenticatedFetch(author, path, {
		method: "POST",
		body: JSON.stringify(request),
	});
	process.stdout.write(
		`${JSON.stringify(await readJson(response), null, 2)}\n`,
	);
}

async function readEnvironment(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project = credential.payload.project;
	const environment =
		option(args, "--environment") ??
		credential.payload.environment ??
		undefined;
	if (project === null || environment === undefined) {
		throw new CliError({
			message: "Environment reads require an Environment credential.",
		});
	}
	const path = `/v1/projects/${project}/environments/${environment}/bundle`;
	const response = await authenticatedFetch(credential, path, {
		method: "GET",
	});
	const bundle = await readJson<SealedBundle>(response);
	const values = await openBundle(bundle, credential);
	process.stdout.write(`${JSON.stringify(values, null, 2)}\n`);
}

async function purgeCache(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project =
		option(args, "--project") ?? credential.payload.project ?? undefined;
	const environment =
		option(args, "--environment") ??
		credential.payload.environment ??
		undefined;
	if (project === undefined || environment === undefined) {
		throw new CliError({
			message:
				"Cache purging requires a credential with one environment scope.",
		});
	}
	const path = `/v1/projects/${project}/environments/${environment}/cache`;
	const response = await authenticatedFetch(credential, path, {
		method: "POST",
	});
	process.stdout.write(
		`${JSON.stringify(await readJson(response), null, 2)}\n`,
	);
}

async function listAudit(args: readonly string[]): Promise<void> {
	const credential = await configuredCredential();
	const project = option(args, "--project") ?? credential.payload.project;
	await listPath(
		project === null ? "/v1/audit" : `/v1/projects/${project}/audit`,
		credential,
	);
}

async function listPath(
	path: string,
	credential?: Awaited<ReturnType<typeof parseCredential>>,
): Promise<void> {
	const configured = credential ?? (await configuredCredential());
	const response = await authenticatedFetch(configured, path, {
		method: "GET",
	});
	writeJson(await readJson(response));
}

function writeJson(value: unknown): void {
	process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function parsePublicDescriptor(value: unknown): CredentialIssueResponse {
	if (
		typeof value !== "object" ||
		value === null ||
		!("payload" in value) ||
		typeof value.payload !== "string" ||
		!("signature" in value) ||
		typeof value.signature !== "string"
	) {
		throw new CliError({ message: "The public credential file is invalid." });
	}
	return { payload: value.payload, signature: value.signature };
}

async function authenticatedFetch(
	credential: Awaited<ReturnType<typeof parseCredential>>,
	path: string,
	init: { method: string; body?: string },
): Promise<Response> {
	const body = new TextEncoder().encode(init.body ?? "");
	const headers = await signRequest(credential, init.method, path, body);
	if (init.body !== undefined) {
		headers.set("content-type", "application/json");
	}
	return fetch(`${credential.payload.api}${path}`, {
		method: init.method,
		headers,
		...(init.body === undefined ? {} : { body: init.body }),
	});
}

async function configuredCredential() {
	return parseCredential(requiredEnv("SECRET_EFFECTS_KEY"));
}

function writeCredential(value: string): void {
	process.stdout.write(`${value}\n`);
	process.stderr.write(
		"Store this credential now. Secret Effects cannot recover its private key.\n",
	);
}

async function readJson<Value = unknown>(response: Response): Promise<Value> {
	const value: unknown = await response.json();
	if (!response.ok) {
		const message =
			typeof value === "object" &&
			value !== null &&
			"error" in value &&
			typeof value.error === "object" &&
			value.error !== null &&
			"message" in value.error &&
			typeof value.error.message === "string"
				? value.error.message
				: `The service returned HTTP ${response.status}.`;
		throw new CliError({ message });
	}
	return value as Value;
}

async function readTextFile(path: string): Promise<string> {
	const { readFile } = await import("node:fs/promises");
	return readFile(path, "utf8");
}

function requiredEnv(name: string): string {
	const value = process.env[name];
	if (value === undefined || value.length === 0) {
		throw new CliError({ message: `${name} is not configured.` });
	}
	return value;
}

function option(args: readonly string[], name: string): string | undefined {
	const index = args.indexOf(name);
	return index === -1 ? undefined : args[index + 1];
}

function options(args: readonly string[], name: string): string[] {
	return args.flatMap((value, index) =>
		value === name && args[index + 1] !== undefined
			? [args[index + 1] as string]
			: [],
	);
}

function requiredOption(args: readonly string[], name: string): string {
	const value = option(args, name);
	if (value === undefined || value.length === 0) {
		throw new CliError({ message: `${name} is required.` });
	}
	return value;
}

function stripTrailingSlash(value: string): string {
	return value.replace(/\/$/, "");
}

function printHelp(): void {
	process.stdout.write(`Secret Effects\n\n`);
	process.stdout.write(`Usage: secreteffects <command>\n\n`);
	process.stdout.write(`  bootstrap --api <url>\n`);
	process.stdout.write(
		`  key issue --type <type> [--project <name>] [--environment <name>]\n`,
	);
	process.stdout.write(`  key list\n`);
	process.stdout.write(`  key public\n`);
	process.stdout.write(`  key inspect\n`);
	process.stdout.write(`  key revoke --id <id> --reason <reason>\n`);
	process.stdout.write(
		`  project create --name <name> [--display-name <name>]\n`,
	);
	process.stdout.write(`  project list\n`);
	process.stdout.write(
		`  environment create --project <name> --environment <name>\n`,
	);
	process.stdout.write(`  environment list --project <name>\n`);
	process.stdout.write(`  schema publish --project <name> --manifest <file>\n`);
	process.stdout.write(`  schema list --project <name>\n`);
	process.stdout.write(
		`  bundle publish --environment <name> --values <file> --schema-digest <hex> [--recipient <key-file>]\n`,
	);
	process.stdout.write(`  environment read [--environment <name>]\n`);
	process.stdout.write(
		`  cache purge [--project <name>] [--environment <name>]\n`,
	);
	process.stdout.write(`  audit list [--project <name>]\n`);
	process.stdout.write(`  tui\n`);
}
