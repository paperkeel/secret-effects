import { readdirSync, readFileSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { parse } from "yaml";

const repositoryRoot = resolve(import.meta.dirname, "..");
const clientPackage = "@paperkeel/secret-effects-client";
const ignoredSourceDirectories = new Set(["node_modules", "dist", ".wrangler"]);
const manifestPaths = [
	"package.json",
	"apps/api/package.json",
	"apps/cli/package.json",
];
const dependencyGroups = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
];

for (const manifestPath of manifestPaths) {
	const manifest = JSON.parse(
		readFileSync(join(repositoryRoot, manifestPath), "utf8"),
	);
	for (const dependencyGroup of dependencyGroups) {
		if (manifest[dependencyGroup]?.[clientPackage] !== undefined) {
			throw new Error(`${manifestPath} must not depend on ${clientPackage}.`);
		}
	}
}

for (const file of sourceFiles(join(repositoryRoot, "apps"))) {
	if (readFileSync(file, "utf8").includes(clientPackage)) {
		throw new Error(
			`${relative(repositoryRoot, file)} must not import ${clientPackage}.`,
		);
	}
}

const deployWorkflow = readFileSync(
	join(repositoryRoot, ".github/workflows/deploy.yml"),
	"utf8",
);
if (
	deployWorkflow.includes(clientPackage) ||
	deployWorkflow.includes("SECRET_EFFECTS_KEY")
) {
	throw new Error(
		"The deploy workflow must use only manual bootstrap credentials.",
	);
}

const releaseWorkflow = readFileSync(
	join(repositoryRoot, ".github/workflows/release.yml"),
	"utf8",
);
const releaseDocument = parse(releaseWorkflow);
const releaseTriggers = releaseDocument?.on;
const releaseBranches = releaseTriggers?.push?.branches;
const publishJob = releaseDocument?.jobs?.["publish-npm"];
if (releaseWorkflow.includes("SECRET_EFFECTS_KEY")) {
	throw new Error(
		"The release workflow must use only manual bootstrap credentials.",
	);
}
if (
	releaseWorkflow.includes("NPM_TOKEN") ||
	releaseWorkflow.includes("NODE_AUTH_TOKEN")
) {
	throw new Error("The release workflow must use npm Trusted Publishing.");
}
if (
	!releaseWorkflow.includes(
		"if: github.repository == 'paperkeel/secret-effects'",
	)
) {
	throw new Error("Only the canonical repository can publish the npm client.");
}
if (
	!Array.isArray(releaseBranches) ||
	!releaseBranches.includes("master") ||
	releaseTriggers?.push?.tags !== undefined
) {
	throw new Error("The release workflow must release each master push.");
}
if (
	publishJob?.["runs-on"] !== "ubuntu-24.04" ||
	publishJob?.environment !== "release" ||
	publishJob?.permissions?.["id-token"] !== "write"
) {
	throw new Error(
		"The npm publish job must use GitHub-hosted Trusted Publishing.",
	);
}
for (const jobName of ["prepare", "finalize"]) {
	if (
		!releaseDocument?.jobs?.[jobName]?.["runs-on"]?.startsWith("blacksmith-")
	) {
		throw new Error(`${jobName} must use a Blacksmith runner.`);
	}
}

process.stdout.write("Bootstrap boundary validation passed.\n");

function sourceFiles(directory) {
	const files = [];
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		if (entry.isDirectory() && ignoredSourceDirectories.has(entry.name)) {
			continue;
		}
		const path = join(directory, entry.name);
		if (entry.isDirectory()) {
			files.push(...sourceFiles(path));
		} else if ([".ts", ".tsx", ".mts", ".cts"].includes(extname(entry.name))) {
			files.push(path);
		}
	}
	return files;
}
