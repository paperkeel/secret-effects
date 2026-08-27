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

export class ProjectState extends DurableObject<ApiEnv> {
	constructor(ctx: DurableObjectState, env: ApiEnv) {
		super(ctx, env);
		void ctx.blockConcurrencyWhile(async () => {
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
		});
	}

	async initialize(): Promise<void> {
		const now = Date.now();
		this.ctx.storage.sql.exec(
			"INSERT OR IGNORE INTO environments(name, is_default, created_at) VALUES (?, 1, ?), (?, 1, ?), (?, 1, ?)",
			DEFAULT_ENVIRONMENTS[0],
			now,
			DEFAULT_ENVIRONMENTS[1],
			now,
			DEFAULT_ENVIRONMENTS[2],
			now,
		);
	}

	async createEnvironment(name: string): Promise<void> {
		this.ctx.storage.sql.exec(
			"INSERT OR IGNORE INTO environments(name, is_default, created_at) VALUES (?, 0, ?)",
			name,
			Date.now(),
		);
	}

	async publish(input: PublishInput): Promise<PublishResult> {
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
				objectKey: replayBeforeUpload.object_key,
				contentVersion: replayBeforeUpload.content_version,
				envelopeVersion: replayBeforeUpload.envelope_version,
				digest: replayBeforeUpload.digest,
				createdAt: replayBeforeUpload.created_at,
				replayed: true,
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

		const outcome = await this.ctx.blockConcurrencyWhile(async () => {
			try {
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
						success: true as const,
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
					return {
						success: false as const,
						message: "The environment changed after the client loaded it.",
					};
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

				this.ctx.storage.transactionSync(() => {
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
				});

				return {
					success: true as const,
					result: {
						objectKey: input.objectKey,
						contentVersion: input.contentVersion,
						envelopeVersion: input.envelopeVersion,
						digest: input.digest,
						createdAt: input.createdAt,
						replayed: false,
					},
				};
			} catch (cause) {
				return {
					success: false as const,
					message:
						cause instanceof Error ? cause.message : "Publication failed.",
				};
			}
		});
		if (!outcome.success) {
			throw new Error(outcome.message);
		}
		return outcome.result;
	}

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

	async audit(
		limit = 100,
	): Promise<readonly Record<string, string | number | null>[]> {
		const safeLimit = Math.max(1, Math.min(limit, 500));
		return this.ctx.storage.sql
			.exec<
				Record<string, string | number | null>
			>("SELECT sequence, previous_hash, event_hash, actor, action, environment, object_digest, created_at FROM audit_events ORDER BY sequence DESC LIMIT ?", safeLimit)
			.toArray();
	}
}

async function digestHex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(value),
	);
	return Array.from(new Uint8Array(digest), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
}
