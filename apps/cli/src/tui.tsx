import { createCliRenderer } from "@opentui/core";
import { createRoot, useKeyboard } from "@opentui/react";
import { useState } from "react";
import { parseCredential, signRequest } from "@secret-effects/crypto";

interface Section {
	title: string;
	value: unknown;
}

const sections = await loadSections().catch((cause: unknown): Section[] => [
	{
		title: "Connection error",
		value: cause instanceof Error ? cause.message : "The request failed.",
	},
]);

function App() {
	const [selected, setSelected] = useState(0);
	useKeyboard((event) => {
		if (event.name === "q" || event.name === "escape") {
			renderer.destroy();
			process.exit(0);
		}
		if (event.name === "left" || event.name === "up") {
			setSelected((current) => Math.max(0, current - 1));
		}
		if (event.name === "right" || event.name === "down") {
			setSelected((current) => Math.min(sections.length - 1, current + 1));
		}
	});

	const current = sections[selected] ?? { title: "No data", value: {} };
	return (
		<box border padding={1} flexDirection="column">
			<text fg="#f59e0b">
				<strong>Secret Effects</strong>
			</text>
			<text>
				{sections
					.map(
						(section, index) =>
							`${index === selected ? "[" : " "}${section.title}${index === selected ? "]" : " "}`,
					)
					.join("  ")}
			</text>
			<text>{JSON.stringify(current.value, null, 2)}</text>
			<text fg="#94a3b8">
				Use arrow keys to inspect sections. Press q or Escape to exit.
			</text>
		</box>
	);
}

async function loadSections(): Promise<Section[]> {
	const rendered = process.env.SECRET_EFFECTS_KEY;
	if (rendered === undefined || rendered.length === 0) {
		throw new Error("SECRET_EFFECTS_KEY is not configured.");
	}
	const credential = await parseCredential(rendered);
	const result: Section[] = [
		{
			title: "Credential",
			value: {
				identifier: credential.payload.identifier,
				type: credential.payload.type,
				project: credential.payload.project,
				environment: credential.payload.environment,
				api: credential.payload.api,
				expiresAt: credential.payload.expiresAt,
			},
		},
	];
	if (["global", "cicd", "agent"].includes(credential.payload.type)) {
		await addRemoteSection(result, "Projects", () =>
			requestJson(credential, "/v1/projects"),
		);
	}
	if (
		["global", "cicd", "project", "agent"].includes(credential.payload.type)
	) {
		await addRemoteSection(result, "Credentials", () =>
			requestJson(credential, "/v1/credentials"),
		);
	}
	if (
		credential.payload.project !== null &&
		["global", "cicd", "project", "agent"].includes(credential.payload.type)
	) {
		await addRemoteSection(result, "Environments", () =>
			requestJson(
				credential,
				`/v1/projects/${credential.payload.project}/environments`,
			),
		);
		await addRemoteSection(result, "Schemas", () =>
			requestJson(
				credential,
				`/v1/projects/${credential.payload.project}/schemas`,
			),
		);
	}
	if (credential.payload.type !== "environment") {
		const path =
			credential.payload.project === null
				? "/v1/audit"
				: `/v1/projects/${credential.payload.project}/audit`;
		await addRemoteSection(result, "Audit", () =>
			requestJson(credential, path),
		);
	}
	return result;
}

async function addRemoteSection(
	sections: Section[],
	title: string,
	load: () => Promise<unknown>,
): Promise<void> {
	try {
		sections.push({ title, value: await load() });
	} catch (cause) {
		sections.push({
			title,
			value: {
				error: cause instanceof Error ? cause.message : "The request failed.",
			},
		});
	}
}

async function requestJson(
	credential: Awaited<ReturnType<typeof parseCredential>>,
	path: string,
): Promise<unknown> {
	const headers = await signRequest(credential, "GET", path, new Uint8Array());
	const response = await fetch(`${credential.payload.api}${path}`, { headers });
	const text = await response.text();
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		throw new Error(
			`Secret Effects returned HTTP ${response.status} with a non-JSON body.`,
		);
	}
	if (!response.ok) {
		throw new Error(`Secret Effects returned HTTP ${response.status}.`);
	}
	return value;
}

const renderer = await createCliRenderer({ exitOnCtrlC: true });
createRoot(renderer).render(<App />);
