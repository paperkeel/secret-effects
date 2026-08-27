/**
 * Serializes encrypted bundle publication for one project.
 *
 * @remarks
 * Responsibility: Owns project environments, current bundle pointers, idempotent publication records, and the project audit chain.
 *
 * Boundary: Accepts encrypted bundle text and storage keys. It does not decrypt bundles or authorize callers.
 */
import { DurableObject } from "cloudflare:workers";
import { DEFAULT_ENVIRONMENTS } from "@secret-effects/protocol";
import type { ApiEnv } from "../../../alchemy.run.ts";

export interface PublishInput {
	environment: string;
	objectKey: string;
	bundle: string;
	baseVersion: string | null;
	contentVersion: string;
	envelopeVersion: string;
	idempotencyKey: string;
	actor: string;
	digest: string;
	createdAt: number;
}

export interface CurrentBundle {
	objectKey: string;
	contentVersion: string;
	envelopeVersion: string;
	digest: string;
	createdAt: number;
}

export interface PublishResult extends CurrentBundle {
	replayed: boolean;
}

export type PublishOutcome =
	| { status: "published"; result: PublishResult }
	| { status: "conflict" };

export class ProjectState extends DurableObject<ApiEnv> {
	/**
	 * Creates a project-state Durable Object and initializes its storage.
	 *
	 * @param ctx - The Cloudflare execution or Durable Object context.
	 * @param env - The Cloudflare resource bindings for the service.
	 */
	constructor(ctx: DurableObjectState, env: ApiEnv) {
		super(ctx, env);
		void ctx.blockConcurrencyWhile(
			/**
			 * Creates project state tables before the object accepts requests.
			 */
			async () => {
				this.ctx.storage.sql.exec(`
				CREATE TABLE IF NOT EXISTS environments (
					name TEXT PRIMARY KEY,
					is_default INTEGER NOT NULL,
					created_at INTEGER NOT NULL
				);
				CREATE TABLE IF NOT EXISTS current_bundles (
					environment TEXT PRIMARY KEY,
					object_key TEXT NOT NULL,
					content_version TEXT NOT NULL,
					envelope_version TEXT NOT NULL,
					digest TEXT NOT NULL,
					created_at INTEGER NOT NULL
				);
				CREATE TABLE IF NOT EXISTS operations (
					idempotency_key TEXT PRIMARY KEY,
					environment TEXT NOT NULL,
					object_key TEXT NOT NULL,
					content_version TEXT NOT NULL,
					envelope_version TEXT NOT NULL,
					digest TEXT NOT NULL,
					created_at INTEGER NOT NULL
				);
				CREATE TABLE IF NOT EXISTS audit_events (
					sequence INTEGER PRIMARY KEY AUTOINCREMENT,
					previous_hash TEXT NOT NULL,
					event_hash TEXT NOT NULL,
					actor TEXT NOT NULL,
					action TEXT NOT NULL,
					environment TEXT,
					object_digest TEXT,
					created_at INTEGER NOT NULL
				);
			`);
			},
		);
	}

	/**
	 * Creates any missing default environments for the project.
	 *
	 * @returns A promise that completes after the operation finishes.
	 */
	async initialize(): Promise<void> {
		const now = Date.now();
		this.ctx.storage.transactionSync(
			/**
			 * Inserts the default environments in one synchronous transaction.
			 */
			() => {
				for (const name of DEFAULT_ENVIRONMENTS) {
					this.ctx.storage.sql.exec(
						"INSERT OR IGNORE INTO environments(name, is_default, created_at) VALUES (?, 1, ?)",
						name,
						now,
					);
				}
			},
		);
	}

	/**
	 * Creates one named environment within a project.
	 *
	 * @param name - The environment, option, header, or variable name for the operation.
	 * @returns A promise that completes after the operation finishes.
	 */
	async createEnvironment(name: string): Promise<void> {
		this.ctx.storage.sql.exec(
			"INSERT OR IGNORE INTO environments(name, is_default, created_at) VALUES (?, 0, ?)",
			name,
			Date.now(),
		);
	}

	/**
	 * Publishes one encrypted bundle with optimistic and idempotent coordination.
	 *
	 * @param input - The validated operation data at this boundary.
	 * @returns The publication outcome with replay or conflict status.
	 */
	async publish(input: PublishInput): Promise<PublishOutcome> {
		const replayBeforeUpload = this.ctx.storage.sql
			.exec<{
				object_key: string;
				content_version: string;
				envelope_version: string;
				digest: string;
				created_at: number;
			}>(
				"SELECT object_key, content_version, envelope_version, digest, created_at FROM operations WHERE idempotency_key = ?",
				input.idempotencyKey,
			)
			.toArray()[0];
		if (replayBeforeUpload !== undefined) {
			return {
				status: "published",
				result: {
					objectKey: replayBeforeUpload.object_key,
					contentVersion: replayBeforeUpload.content_version,
					envelopeVersion: replayBeforeUpload.envelope_version,
					digest: replayBeforeUpload.digest,
					createdAt: replayBeforeUpload.created_at,
					replayed: true,
				},
			};
		}

		await this.env.BUNDLES.put(input.objectKey, input.bundle, {
			httpMetadata: {
				contentType: "application/vnd.secret-effects.bundle+json",
			},
			customMetadata: {
				contentVersion: input.contentVersion,
				envelopeVersion: input.envelopeVersion,
				digest: input.digest,
			},
		});

		return this.ctx.blockConcurrencyWhile(
			/**
			 * Serializes one bundle publication after object storage succeeds.
			 *
			 * @returns The publication outcome after serialized coordination.
			 */
			async () => {
				const replay = this.ctx.storage.sql
					.exec<{
						object_key: string;
						content_version: string;
						envelope_version: string;
						digest: string;
						created_at: number;
					}>(
						"SELECT object_key, content_version, envelope_version, digest, created_at FROM operations WHERE idempotency_key = ?",
						input.idempotencyKey,
					)
					.toArray()[0];
				if (replay !== undefined) {
					return {
						status: "published" as const,
						result: {
							objectKey: replay.object_key,
							contentVersion: replay.content_version,
							envelopeVersion: replay.envelope_version,
							digest: replay.digest,
							createdAt: replay.created_at,
							replayed: true,
						},
					};
				}

				const before = await this.current(input.environment);
				if ((before?.contentVersion ?? null) !== input.baseVersion) {
					return { status: "conflict" as const };
				}

				const previous =
					this.ctx.storage.sql
						.exec<{
							event_hash: string;
						}>(
							"SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
						)
						.toArray()[0]?.event_hash ?? "0".repeat(64);
				const eventMaterial = [
					previous,
					input.actor,
					"bundle.publish",
					input.environment,
					input.digest,
					String(input.createdAt),
				].join("\n");
				const eventHash = await digestHex(eventMaterial);

				this.ctx.storage.transactionSync(
					/**
					 * Commits bundle pointers, idempotency data, and audit data atomically.
					 */
					() => {
						this.ctx.storage.sql.exec(
							`INSERT INTO current_bundles(environment, object_key, content_version, envelope_version, digest, created_at)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(environment) DO UPDATE SET
				 object_key = excluded.object_key,
				 content_version = excluded.content_version,
				 envelope_version = excluded.envelope_version,
				 digest = excluded.digest,
				 created_at = excluded.created_at`,
							input.environment,
							input.objectKey,
							input.contentVersion,
							input.envelopeVersion,
							input.digest,
							input.createdAt,
						);
						this.ctx.storage.sql.exec(
							"INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?)",
							input.idempotencyKey,
							input.environment,
							input.objectKey,
							input.contentVersion,
							input.envelopeVersion,
							input.digest,
							input.createdAt,
						);
						this.ctx.storage.sql.exec(
							"INSERT INTO audit_events(previous_hash, event_hash, actor, action, environment, object_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
							previous,
							eventHash,
							input.actor,
							"bundle.publish",
							input.environment,
							input.digest,
							input.createdAt,
						);
					},
				);

				return {
					status: "published" as const,
					result: {
						objectKey: input.objectKey,
						contentVersion: input.contentVersion,
						envelopeVersion: input.envelopeVersion,
						digest: input.digest,
						createdAt: input.createdAt,
						replayed: false,
					},
				};
			},
		);
	}

	/**
	 * Reads the current encrypted bundle pointer for one environment.
	 *
	 * @param environment - The machine name of the target environment.
	 * @returns The current bundle pointer, or null when none exists.
	 */
	async current(environment: string): Promise<CurrentBundle | null> {
		const row = this.ctx.storage.sql
			.exec<{
				object_key: string;
				content_version: string;
				envelope_version: string;
				digest: string;
				created_at: number;
			}>(
				"SELECT object_key, content_version, envelope_version, digest, created_at FROM current_bundles WHERE environment = ?",
				environment,
			)
			.toArray()[0];
		return row === undefined
			? null
			: {
					objectKey: row.object_key,
					contentVersion: row.content_version,
					envelopeVersion: row.envelope_version,
					digest: row.digest,
					createdAt: row.created_at,
				};
	}

	/**
	 * Gets the global audit Durable Object stub.
	 *
	 * @param limit - The requested maximum number of audit events.
	 * @returns The global audit object stub.
	 */
	async audit(
		limit = 100,
	): Promise<readonly Record<string, string | number | null>[]> {
		const safeLimit = Math.max(1, Math.min(limit, 500));
		return this.ctx.storage.sql
			.exec<Record<string, string | number | null>>(
				"SELECT sequence, previous_hash, event_hash, actor, action, environment, object_digest, created_at FROM audit_events ORDER BY sequence DESC LIMIT ?",
				safeLimit,
			)
			.toArray();
	}
}

/**
 * Computes a lowercase SHA-256 digest for text.
 *
 * @param value - The project audit hash material to digest.
 * @returns The lowercase SHA-256 digest.
 */
async function digestHex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(value),
	);
	return Array.from(new Uint8Array(digest), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
}
