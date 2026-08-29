/**
 * Defines shared Secret Effects wire schemas and canonical names.
 *
 * @remarks
 * Responsibility: Owns protocol constants, Effect schemas, canonical JSON encoding, cache tags, object keys, and request decoders.
 *
 * Boundary: Validates structural protocol data. It does not authenticate requests, persist records, or encrypt bundles.
 */
import * as Schema from "effect/Schema";

export const CREDENTIAL_PREFIX = "secret_effects_v1";
export const MASTER_KEY_BYTES = 64;
export const MASTER_KEY_HEX_LENGTH = MASTER_KEY_BYTES * 2;
export const CHECKSUM_HEX_LENGTH = 32;
export const DEFAULT_ENVIRONMENTS = ["local", "dev", "production"] as const;
export const MACHINE_NAME_PATTERN = /^[a-z][a-z0-9]*$/;
export const ENVIRONMENT_KEY_PATTERN = /^[A-Z][A-Z0-9_]*$/;

const MachineName = Schema.String.check(Schema.isPattern(MACHINE_NAME_PATTERN));
const CredentialIdentifier = Schema.String.check(
	Schema.isPattern(/^[0-9a-f]{32}$/),
);
const PublicKey = Schema.String.check(Schema.isPattern(/^[0-9a-f]{64}$/));
const BundleVersion = Schema.String.check(Schema.isPattern(/^[0-9a-f]{64}$/));
const FiniteTimestamp = Schema.Number.check(Schema.isFinite());

export const CredentialType = Schema.Literals([
	"global",
	"cicd",
	"project",
	"agent",
	"environment",
]);
export type CredentialType = typeof CredentialType.Type;

export const CredentialPayload = Schema.Struct({
	version: Schema.Literal(1),
	api: Schema.String,
	issuer: Schema.String,
	issuerPublicKey: PublicKey,
	type: CredentialType,
	project: Schema.NullOr(MachineName),
	environment: Schema.NullOr(MachineName),
	identifier: CredentialIdentifier,
	authPublicKey: PublicKey,
	decryptPublicKey: Schema.NullOr(PublicKey),
	issuedAt: Schema.Number,
	notBefore: Schema.Number,
	expiresAt: Schema.NullOr(Schema.Number),
});
export type CredentialPayload = typeof CredentialPayload.Type;

export const CredentialIssueRequest = Schema.Struct({
	type: CredentialType,
	project: Schema.NullOr(MachineName),
	environment: Schema.NullOr(MachineName),
	authPublicKey: PublicKey,
	decryptPublicKey: Schema.NullOr(PublicKey),
	expiresAt: Schema.NullOr(FiniteTimestamp),
});
export type CredentialIssueRequest = typeof CredentialIssueRequest.Type;

export const CredentialIssueResponse = Schema.Struct({
	payload: Schema.String,
	signature: Schema.String,
});
export type CredentialIssueResponse = typeof CredentialIssueResponse.Type;

export const SealedRecipient = Schema.Struct({
	identifier: CredentialIdentifier,
	ephemeralPublicKey: Schema.String,
	nonce: Schema.String,
	wrappedKey: Schema.String,
});
export type SealedRecipient = typeof SealedRecipient.Type;

export const SealedBundle = Schema.Struct({
	format: Schema.Literal("secret-effects-bundle-v1"),
	project: Schema.String,
	environment: Schema.String,
	contentVersion: BundleVersion,
	envelopeVersion: BundleVersion,
	schemaDigest: Schema.String,
	createdAt: Schema.Number,
	nonce: Schema.String,
	ciphertext: Schema.String,
	recipients: Schema.Array(SealedRecipient),
	author: CredentialIdentifier,
	authorPublicKey: PublicKey,
	signature: Schema.String,
	serviceSignature: Schema.NullOr(Schema.String),
});
export type SealedBundle = typeof SealedBundle.Type;

export const PublishBundleRequest = Schema.Struct({
	baseVersion: Schema.NullOr(Schema.String),
	idempotencyKey: Schema.String,
	bundle: SealedBundle,
});
export type PublishBundleRequest = typeof PublishBundleRequest.Type;

export const ProjectCreateRequest = Schema.Struct({
	name: MachineName,
	displayName: Schema.String,
});
export type ProjectCreateRequest = typeof ProjectCreateRequest.Type;

export const EnvironmentCreateRequest = Schema.Struct({
	name: MachineName,
});
export type EnvironmentCreateRequest = typeof EnvironmentCreateRequest.Type;

export const CredentialRevokeRequest = Schema.Struct({
	reason: Schema.String,
});
export type CredentialRevokeRequest = typeof CredentialRevokeRequest.Type;

export const SchemaManifestRequest = Schema.Struct({
	digest: Schema.String,
	manifest: Schema.Unknown,
});
export type SchemaManifestRequest = typeof SchemaManifestRequest.Type;

export const PurgeMessage = Schema.Struct({
	project: Schema.String,
	environment: Schema.String,
	tag: Schema.String,
	attempt: Schema.Number,
});
export type PurgeMessage = typeof PurgeMessage.Type;

/**
 * Rejects a value that is not a valid machine name.
 *
 * @param value - The machine name to validate.
 * @param label - The human-readable name for validation errors.
 * @throws {@link Error} When the input cannot satisfy the protocol boundary.
 */
export function assertMachineName(value: string, label: string): void {
	if (!MACHINE_NAME_PATTERN.test(value)) {
		throw new Error(
			`${label} must contain lowercase ASCII letters and numbers only.`,
		);
	}
}

/**
 * Serializes a supported value as canonical JSON text.
 *
 * @param value - The supported value to serialize.
 * @returns The canonical JSON text.
 */
export function canonicalJson(value: unknown): string {
	return canonicalJsonValue(value, new Set<object>());
}

/**
 * Serializes one supported value while tracking ancestor objects.
 *
 * @param value - The current supported value to serialize.
 * @param ancestors - The active object ancestry used to detect cycles.
 * @returns The canonical JSON fragment.
 * @throws {@link Error} When the input cannot satisfy the protocol boundary.
 */
function canonicalJsonValue(value: unknown, ancestors: Set<object>): string {
	if (value === null) {
		return "null";
	}
	if (typeof value === "string" || typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) {
			throw new TypeError("Canonical JSON accepts only finite numbers.");
		}
		return JSON.stringify(value);
	}
	if (typeof value !== "object") {
		throw new TypeError("Canonical JSON contains an unsupported value.");
	}
	if (ancestors.has(value)) {
		throw new TypeError("Canonical JSON cannot contain a cycle.");
	}
	ancestors.add(value);
	try {
		if (Array.isArray(value)) {
			return `[${value.map((item) => canonicalJsonValue(item, ancestors)).join(",")}]`;
		}
		const prototype = Object.getPrototypeOf(value);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new TypeError("Canonical JSON accepts only plain objects.");
		}
		const record = value as Record<string, unknown>;
		return `{${Object.keys(record)
			.sort()
			.map(
				(key) =>
					`${JSON.stringify(key)}:${canonicalJsonValue(record[key], ancestors)}`,
			)
			.join(",")}}`;
	} finally {
		ancestors.delete(value);
	}
}

/**
 * Builds the cache tag for one project environment.
 *
 * @param project - The machine name of the target project.
 * @param environment - The machine name of the target environment.
 * @returns The stable environment cache tag.
 */
export function environmentCacheTag(
	project: string,
	environment: string,
): string {
	return `se-${project}-${environment}`;
}

/**
 * Builds the immutable object key for an encrypted bundle version.
 *
 * @param bundle - The encrypted bundle or test draft for the operation.
 * @returns The immutable R2 object key.
 */
export function bundleObjectKey(bundle: SealedBundle): string {
	return [
		"bundles",
		bundle.project,
		bundle.environment,
		bundle.contentVersion,
		`${bundle.envelopeVersion}.secrets`,
	].join("/");
}

/**
 * Decodes and validates a credential issue request.
 *
 * @param value - The unknown credential issue request data.
 * @returns The validated credential issue request.
 */
export function decodeCredentialIssueRequest(
	value: unknown,
): CredentialIssueRequest {
	return Schema.decodeUnknownSync(CredentialIssueRequest)(value);
}

/**
 * Decodes and validates an encrypted bundle publication request.
 *
 * @param value - The unknown bundle publication request data.
 * @returns The validated bundle publication request.
 */
export function decodePublishBundleRequest(
	value: unknown,
): PublishBundleRequest {
	return Schema.decodeUnknownSync(PublishBundleRequest)(value);
}

/**
 * Decodes and validates a project creation request.
 *
 * @param value - The unknown project creation request data.
 * @returns The validated project creation request.
 */
export function decodeProjectCreateRequest(
	value: unknown,
): ProjectCreateRequest {
	return Schema.decodeUnknownSync(ProjectCreateRequest)(value);
}

/**
 * Decodes and validates an environment creation request.
 *
 * @param value - The unknown environment creation request data.
 * @returns The validated environment creation request.
 */
export function decodeEnvironmentCreateRequest(
	value: unknown,
): EnvironmentCreateRequest {
	return Schema.decodeUnknownSync(EnvironmentCreateRequest)(value);
}

/**
 * Decodes and validates a cache purge message.
 *
 * @param value - The unknown cache purge message data.
 * @returns The validated cache purge message.
 */
export function decodePurgeMessage(value: unknown): PurgeMessage {
	return Schema.decodeUnknownSync(PurgeMessage)(value);
}

/**
 * Decodes and validates a credential revocation request.
 *
 * @param value - The unknown credential revocation request data.
 * @returns The validated credential revocation request.
 */
export function decodeCredentialRevokeRequest(
	value: unknown,
): CredentialRevokeRequest {
	return Schema.decodeUnknownSync(CredentialRevokeRequest)(value);
}

/**
 * Decodes and validates a schema manifest request.
 *
 * @param value - The unknown schema manifest request data.
 * @returns The validated schema manifest request.
 */
export function decodeSchemaManifestRequest(
	value: unknown,
): SchemaManifestRequest {
	return Schema.decodeUnknownSync(SchemaManifestRequest)(value);
}
