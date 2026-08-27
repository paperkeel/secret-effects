/**
 * Provisions Cloudflare infrastructure for Secret Effects deployments.
 *
 * @remarks
 * Responsibility: Owns stage validation and construction of the Worker, storage, queue, cache, and runtime bindings.
 *
 * Boundary: Accepts Alchemy stage and process configuration. It delegates request behavior to the API application.
 */
import * as Alchemy from "alchemy";
import { adopt } from "alchemy/AdoptPolicy";
import * as Cloudflare from "alchemy/Cloudflare";
import { retain } from "alchemy/RemovalPolicy";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import type { AuditLog } from "./apps/api/src/audit-log.ts";
import type { ProjectState } from "./apps/api/src/project-state.ts";

const COMPATIBILITY_DATE = "2026-08-27";

export interface ApiEnv {
	CATALOG: D1Database;
	BUNDLES: R2Bucket;
	PURGE_QUEUE: Queue<unknown>;
	PROJECTS: DurableObjectNamespace<ProjectState>;
	AUDIT: DurableObjectNamespace<AuditLog>;
	ISSUER_PRIVATE_KEY: string;
	GLOBAL_ADMIN_TOKEN: string;
	ISSUER_ID: string;
	API_ORIGIN: string;
	SENTRY_DSN?: string;
	SENTRY_ENVIRONMENT: string;
	SENTRY_RELEASE: string;
}

export default Alchemy.Stack(
	"secret-effects",
	{
		providers: Cloudflare.providers(),
		state: Cloudflare.state(),
	},
	Effect.gen(
		/**
		 * Defines the stage-specific Cloudflare resource graph.
		 *
		 * @returns The deployed Worker names and resource identifiers.
		 */
		function* () {
			const stage = yield* Alchemy.Stage;
			if (stage !== "prod" && stage !== "dev") {
				return yield* Effect.die(
					new Error("The stack supports only dev and prod stages."),
				);
			}
			const production = stage === "prod";
			const suffix = production ? "" : `-${stage}`;
			const configuredApiOrigin =
				process.env.SECRET_EFFECTS_API_URL ??
				(production ? undefined : "http://127.0.0.1:8787");
			if (configuredApiOrigin === undefined) {
				return yield* Effect.die(
					new Error("SECRET_EFFECTS_API_URL is required for production."),
				);
			}
			let apiOrigin: string;
			try {
				const apiUrl = new URL(configuredApiOrigin);
				if (production && apiUrl.protocol !== "https:") {
					return yield* Effect.die(
						new Error("SECRET_EFFECTS_API_URL must use HTTPS in production."),
					);
				}
				apiOrigin = apiUrl.origin;
			} catch {
				return yield* Effect.die(
					new Error("SECRET_EFFECTS_API_URL must be an absolute URL."),
				);
			}
			const deploymentSha =
				process.env.DEPLOY_SHA ?? process.env.GITHUB_SHA ?? "local";
			const sentryDsn = process.env.SENTRY_DSN || undefined;

			const catalog = yield* Cloudflare.D1.Database("Catalog", {
				name: `secret-effects-catalog${suffix}`,
				migrations: "./migrations",
				primaryLocationHint: "wnam",
			});
			const bundles = yield* Cloudflare.R2.Bucket("Bundles", {
				name: `secret-effects-bundles${suffix}`,
			});
			const purgeQueue = yield* Cloudflare.Queues.Queue("PurgeQueue", {
				name: `secret-effects-purge${suffix}`,
			});

			const worker = yield* Cloudflare.Worker("Api", {
				name: `secret-effects-api${suffix}`,
				main: "apps/api/src/index.ts",
				compatibility: {
					date: COMPATIBILITY_DATE,
					flags: ["nodejs_compat"],
				},
				workersDev: true,
				cache: {
					enabled: true,
					crossVersionCache: true,
				},
				observability: {
					enabled: true,
					headSamplingRate: 1,
					logs: {
						enabled: true,
						headSamplingRate: 1,
						invocationLogs: true,
						persist: true,
					},
				},
				env: {
					CATALOG: catalog,
					BUNDLES: bundles,
					PURGE_QUEUE: purgeQueue,
					PROJECTS: Cloudflare.DurableObject<ProjectState>("PROJECTS", {
						className: "ProjectState",
					}),
					AUDIT: Cloudflare.DurableObject<AuditLog>("AUDIT", {
						className: "AuditLog",
					}),
					ISSUER_PRIVATE_KEY: Config.redacted(
						"SECRET_EFFECTS_ISSUER_PRIVATE_KEY",
					),
					GLOBAL_ADMIN_TOKEN: Config.redacted(
						"SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN",
					),
					ISSUER_ID: "secreteffectsroot2026",
					API_ORIGIN: apiOrigin,
					...(sentryDsn === undefined
						? {}
						: { SENTRY_DSN: Config.redacted("SENTRY_DSN") }),
					SENTRY_ENVIRONMENT: stage,
					SENTRY_RELEASE: deploymentSha,
				},
				version: {
					message:
						deploymentSha === "local" ? "local deployment" : deploymentSha,
					tag: deploymentSha,
				},
			}).pipe(adopt(production), retain());

			yield* Cloudflare.Queues.Consumer("PurgeConsumer", {
				queueId: purgeQueue.queueId,
				scriptName: worker.workerName,
				settings: {
					batchSize: 10,
					maxRetries: 5,
					maxWaitTimeMs: 1_000,
				},
			});

			return {
				apiUrl: worker.url,
				workerName: worker.workerName,
				catalogName: catalog.databaseName,
				bundleBucket: bundles.bucketName,
				purgeQueue: purgeQueue.queueName,
			};
		},
	),
);
