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
	BOOTSTRAP_TOKEN: string;
	ISSUER_ID: string;
}

export default Alchemy.Stack(
	"secret-effects",
	{
		providers: Cloudflare.providers(),
		state: Cloudflare.state(),
	},
	Effect.gen(function* () {
		const stage = yield* Alchemy.Stage;
		if (stage !== "prod" && stage !== "dev") {
			return yield* Effect.die(
				new Error("The stack supports only dev and prod stages."),
			);
		}
		const production = stage === "prod";
		const suffix = production ? "" : `-${stage}`;

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
				BOOTSTRAP_TOKEN: Config.redacted("SECRET_EFFECTS_BOOTSTRAP_TOKEN"),
				ISSUER_ID: "secreteffectsroot2026",
			},
			version: {
				message: process.env.GITHUB_SHA ?? "local deployment",
				tag: process.env.GITHUB_SHA ?? "local",
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
	}),
);
