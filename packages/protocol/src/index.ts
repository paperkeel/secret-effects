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
	expiresAt: Schema.NullOr(Schema.Number),
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
	contentVersion: Schema.String,
	envelopeVersion: Schema.String,
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

export function assertMachineName(value: string, label: string): void {
	if (!MACHINE_NAME_PATTERN.test(value)) {
		throw new Error(
			`${label} must contain lowercase ASCII letters and numbers only.`,
		);
	}
}

export function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}

export function environmentCacheTag(
	project: string,
	environment: string,
): string {
	return `se-${project}-${environment}`;
}

export function bundleObjectKey(bundle: SealedBundle): string {
	return [
		"bundles",
		bundle.project,
		bundle.environment,
		bundle.contentVersion,
		`${bundle.envelopeVersion}.secrets`,
	].join("/");
}

export function decodeCredentialIssueRequest(
	value: unknown,
): CredentialIssueRequest {
	return Schema.decodeUnknownSync(CredentialIssueRequest)(value);
}

export function decodePublishBundleRequest(
	value: unknown,
): PublishBundleRequest {
	return Schema.decodeUnknownSync(PublishBundleRequest)(value);
}

export function decodeProjectCreateRequest(
	value: unknown,
): ProjectCreateRequest {
	return Schema.decodeUnknownSync(ProjectCreateRequest)(value);
}

export function decodeEnvironmentCreateRequest(
	value: unknown,
): EnvironmentCreateRequest {
	return Schema.decodeUnknownSync(EnvironmentCreateRequest)(value);
}

export function decodePurgeMessage(value: unknown): PurgeMessage {
	return Schema.decodeUnknownSync(PurgeMessage)(value);
}

export function decodeCredentialRevokeRequest(
	value: unknown,
): CredentialRevokeRequest {
	return Schema.decodeUnknownSync(CredentialRevokeRequest)(value);
}

export function decodeSchemaManifestRequest(
	value: unknown,
): SchemaManifestRequest {
	return Schema.decodeUnknownSync(SchemaManifestRequest)(value);
}
