import { describe, expect, it } from "vitest";
import { canonicalJson } from "./index.ts";

describe("canonicalJson", () => {
	it("orders object keys without changing array order", () => {
		expect(canonicalJson({ z: [3, 2, 1], a: { d: true, c: null } })).toBe(
			'{"a":{"c":null,"d":true},"z":[3,2,1]}',
		);
	});

	it.each([undefined, 1n, Symbol("value"), () => undefined, Number.NaN])(
		"rejects an unsupported value",
		(value) => {
			expect(() => canonicalJson({ value })).toThrow();
		},
	);

	it("rejects cycles", () => {
		const value: Record<string, unknown> = {};
		value.self = value;
		expect(() => canonicalJson(value)).toThrow("cycle");
	});
});
