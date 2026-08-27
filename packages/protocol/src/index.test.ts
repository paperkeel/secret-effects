/**
 * Tests canonical JSON behavior at protocol boundaries.
 *
 * @remarks
 * Responsibility: Owns regression coverage for key ordering, array stability, unsupported values, and cycles.
 *
 * Boundary: Uses local data only. It does not validate credentials or access service resources.
 */
import { describe, expect, it } from "vitest";
import { canonicalJson } from "./index.ts";

describe("canonicalJson", canonicalJsonTests);

/**
 * Groups canonical JSON tests.
 */
function canonicalJsonTests() {
	it("orders object keys without changing array order", ordersObjectKeys);
	it.each([undefined, 1n, Symbol("value"), () => undefined, Number.NaN])(
		"rejects an unsupported value",
		rejectsUnsupportedValue,
	);
	it("rejects cycles", rejectsCycles);
}

/**
 * Tests object-key sorting without array reordering.
 */
function ordersObjectKeys() {
	expect(canonicalJson({ z: [3, 2, 1], a: { d: true, c: null } })).toBe(
		'{"a":{"c":null,"d":true},"z":[3,2,1]}',
	);
}

/**
 * Tests rejection of one unsupported canonical JSON value.
 *
 * @param value - The unsupported value at the canonical JSON boundary.
 */
function rejectsUnsupportedValue(value: unknown) {
	expect(() => canonicalJson({ value })).toThrow();
}

/**
 * Tests rejection of cyclic canonical JSON data.
 */
function rejectsCycles() {
	const value: Record<string, unknown> = {};
	value.self = value;
	expect(() => canonicalJson(value)).toThrow("cycle");
}
