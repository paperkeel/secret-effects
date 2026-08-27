/**
 * Persists the global Secret Effects audit hash chain.
 *
 * @remarks
 * Responsibility: Owns ordered audit event storage, idempotent appends, and bounded audit queries.
 *
 * Boundary: Accepts digested audit details. It does not store secret values or authorize actions.
 */
import { DurableObject } from "cloudflare:workers";
import type { ApiEnv } from "../../../alchemy.run.ts";

export interface AuditInput {
	eventId: string;
	actor: string;
	action: string;
	project: string | null;
	environment: string | null;
	subject: string | null;
	detailsDigest: string;
	createdAt: number;
}

export interface AuditEvent extends AuditInput {
	sequence: number;
	previousHash: string;
	eventHash: string;
}

export class AuditLog extends DurableObject<ApiEnv> {
	/**
	 * Creates an audit log Durable Object and initializes its storage.
	 *
	 * @param ctx - The Cloudflare execution or Durable Object context.
	 * @param env - The Cloudflare resource bindings for the service.
	 */
	constructor(ctx: DurableObjectState, env: ApiEnv) {
		super(ctx, env);
		void ctx.blockConcurrencyWhile(
			/**
			 * Creates the audit event table before the object accepts requests.
			 */
			async () => {
				this.ctx.storage.sql.exec(`
				CREATE TABLE IF NOT EXISTS audit_events (
					sequence INTEGER PRIMARY KEY AUTOINCREMENT,
					event_id TEXT NOT NULL UNIQUE,
					previous_hash TEXT NOT NULL,
					event_hash TEXT NOT NULL UNIQUE,
					actor TEXT NOT NULL,
					action TEXT NOT NULL,
					project TEXT,
					environment TEXT,
					subject TEXT,
					details_digest TEXT NOT NULL,
					created_at INTEGER NOT NULL
				);
			`);
			},
		);
	}

	/**
	 * Appends one idempotent event to the global audit hash chain.
	 *
	 * @param input - The validated operation data at this boundary.
	 * @returns The existing or newly stored audit event.
	 */
	async append(input: AuditInput): Promise<AuditEvent> {
		return this.ctx.blockConcurrencyWhile(
			/**
			 * Serializes one idempotent audit append.
			 *
			 * @returns The existing or newly stored audit event.
			 * @throws {@link ApiError} When request data, access, or service state violates an API boundary.
			 */
			async () => {
				const existing = this.ctx.storage.sql
					.exec<AuditRow>(
						"SELECT * FROM audit_events WHERE event_id = ?",
						input.eventId,
					)
					.toArray()[0];
				if (existing !== undefined) {
					return fromRow(existing);
				}
				const previousHash =
					this.ctx.storage.sql
						.exec<{
							event_hash: string;
						}>(
							"SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
						)
						.toArray()[0]?.event_hash ?? "0".repeat(64);
				const eventHash = await digestHex(
					[
						previousHash,
						input.eventId,
						input.actor,
						input.action,
						input.project ?? "",
						input.environment ?? "",
						input.subject ?? "",
						input.detailsDigest,
						String(input.createdAt),
					].join("\n"),
				);
				this.ctx.storage.sql.exec(
					`INSERT INTO audit_events(event_id, previous_hash, event_hash, actor, action, project, environment, subject, details_digest, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					input.eventId,
					previousHash,
					eventHash,
					input.actor,
					input.action,
					input.project,
					input.environment,
					input.subject,
					input.detailsDigest,
					input.createdAt,
				);
				const created = this.ctx.storage.sql
					.exec<AuditRow>(
						"SELECT * FROM audit_events WHERE event_id = ?",
						input.eventId,
					)
					.toArray()[0];
				if (created === undefined) {
					throw new Error("The audit event was not stored.");
				}
				return fromRow(created);
			},
		);
	}

	/**
	 * Lists recent global audit events with an optional project filter.
	 *
	 * @param project - The machine name of the target project.
	 * @param limit - The requested maximum number of audit events.
	 * @returns The matching audit events in descending sequence order.
	 */
	async list(
		project: string | null,
		limit = 100,
	): Promise<readonly AuditEvent[]> {
		const safeLimit = Math.max(1, Math.min(limit, 500));
		const rows =
			project === null
				? this.ctx.storage.sql
						.exec<AuditRow>(
							"SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?",
							safeLimit,
						)
						.toArray()
				: this.ctx.storage.sql
						.exec<AuditRow>(
							"SELECT * FROM audit_events WHERE project = ? ORDER BY sequence DESC LIMIT ?",
							project,
							safeLimit,
						)
						.toArray();
		return rows.map(fromRow);
	}
}

interface AuditRow extends Record<string, SqlStorageValue> {
	sequence: number;
	event_id: string;
	previous_hash: string;
	event_hash: string;
	actor: string;
	action: string;
	project: string | null;
	environment: string | null;
	subject: string | null;
	details_digest: string;
	created_at: number;
}

/**
 * Converts a stored audit row into a public audit event.
 *
 * @param row - The stored audit row to convert.
 * @returns The public audit event.
 */
function fromRow(row: AuditRow): AuditEvent {
	return {
		sequence: row.sequence,
		eventId: row.event_id,
		previousHash: row.previous_hash,
		eventHash: row.event_hash,
		actor: row.actor,
		action: row.action,
		project: row.project,
		environment: row.environment,
		subject: row.subject,
		detailsDigest: row.details_digest,
		createdAt: row.created_at,
	};
}

/**
 * Computes a lowercase SHA-256 digest for text.
 *
 * @param value - The audit hash material to digest.
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
