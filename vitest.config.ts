/**
 * Configures repository tests and coverage reporting.
 *
 * @remarks
 * Responsibility: Owns the shared Vitest environment and coverage reporter settings.
 *
 * Boundary: Applies to repository test suites. It does not define test behavior.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		environment: "node",
		coverage: {
			provider: "v8",
			reporter: ["text", "json-summary"],
		},
	},
});
