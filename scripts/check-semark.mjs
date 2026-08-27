import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import ts from "typescript";

const repositoryRoot = resolve(import.meta.dirname, "..");
const sourceRoots = [
	repositoryRoot,
	join(repositoryRoot, "apps"),
	join(repositoryRoot, "packages"),
];
const sourceExtensions = [".ts", ".tsx", ".mts", ".cts"];
const ignoredDirectories = new Set([
	".git",
	".alchemy",
	".wrangler",
	"coverage",
	"dist",
	"node_modules",
]);
const directivePatterns = [
	/^\/\/\s*@ts-(?:check|nocheck|ignore|expect-error)\b/,
	/^\/\/\s*(?:oxlint|eslint)-(?:disable|enable|disable-line|disable-next-line)\b/,
	/^\/\/\s*(?:oxfmt|prettier)-ignore\b/,
	/^\/\/\/\s*<(?:reference|amd-module|amd-dependency|types)\b[^>]*\/>/,
	/^\/\/\s*(?:c8|v8|istanbul)\s+ignore\b/,
	/^\/\/\s*(?:SPDX-License-Identifier:|Copyright\b)/i,
	/^\/\/\s*(?:@generated\b|Code generated\b)/i,
	/^\/\*\s*(?:oxlint|eslint)-(?:disable|enable)\b[\s\S]*\*\/$/,
	/^\/\*\s*(?:oxfmt|prettier)-ignore\b[\s\S]*\*\/$/,
	/^\/\*\s*(?:c8|v8|istanbul)\s+ignore\b[\s\S]*\*\/$/,
	/^\/\*[\s\S]*(?:SPDX-License-Identifier:|Copyright\b)[\s\S]*\*\/$/i,
	/^\/\*[\s\S]*(?:@generated\b|Code generated\b)[\s\S]*\*\/$/i,
];
const remarksLabels = [
	"Side effects",
	"Invariant",
	"Constraint",
	"Assumption",
	"Interaction",
];
const tagOrder = [
	"typeParam",
	"param",
	"returns",
	"throws",
	"deprecated",
	"example",
	"see",
];
const errors = [];

function report(file, position, type, message) {
	const source = readFileSync(file, "utf8");
	const before = source.slice(0, position);
	const line = before.split("\n").length;
	const column = position - before.lastIndexOf("\n");
	errors.push(
		`${relative(repositoryRoot, file)}:${line}:${column} [${type}] ${message}`,
	);
}

function listFiles(directory, recursive = true) {
	const files = [];
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) {
			if (recursive && !ignoredDirectories.has(entry.name)) {
				files.push(...listFiles(path));
			}
			continue;
		}
		if (
			sourceExtensions.some((extension) => entry.name.endsWith(extension)) &&
			!entry.name.endsWith(".d.ts")
		) {
			files.push(path);
		}
	}
	return files;
}

function applicableFiles() {
	const rootFiles = listFiles(sourceRoots[0], false);
	return [
		...rootFiles,
		...listFiles(sourceRoots[1]),
		...listFiles(sourceRoots[2]),
	].sort((left, right) => left.localeCompare(right));
}

function commentsIn(source, sourceFile) {
	const comments = new Map();
	function addRanges(ranges) {
		for (const range of ranges ?? []) {
			comments.set(range.pos, {
				start: range.pos,
				end: range.end,
				raw: source.slice(range.pos, range.end),
			});
		}
	}
	function visit(node) {
		addRanges(ts.getLeadingCommentRanges(source, node.getFullStart()));
		addRanges(ts.getTrailingCommentRanges(source, node.getFullStart()));
		addRanges(ts.getTrailingCommentRanges(source, node.end));
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	return [...comments.values()].sort((left, right) => left.start - right.start);
}

function commentLines(raw) {
	const physical = raw.split(/\r?\n/);
	if (
		physical.length < 3 ||
		physical[0].trim() !== "/**" ||
		physical.at(-1)?.trim() !== "*/"
	) {
		return null;
	}
	const lines = [];
	for (const line of physical.slice(1, -1)) {
		const match = /^\s*\*(?: ?(.*))?$/.exec(line);
		if (match === null) {
			return null;
		}
		lines.push((match[1] ?? "").trimEnd());
	}
	return lines;
}

function countWords(text) {
	return text.match(/[\p{L}\p{N}][\p{L}\p{N}'-]*/gu)?.length ?? 0;
}

function countSentences(text) {
	return text.match(/[.!?](?:["')\]}]+)?(?=\s|$)/g)?.length ?? 0;
}

function readParagraph(lines, start) {
	let end = start;
	while (end < lines.length && lines[end] !== "") {
		end += 1;
	}
	return { end, text: lines.slice(start, end).join(" ").trim() };
}

function validateSummary(summary) {
	return (
		summary.length > 0 &&
		countSentences(summary) === 1 &&
		countWords(summary) <= 25
	);
}

function parseFileSignature(raw) {
	const lines = commentLines(raw);
	if (lines === null) {
		return {
			errors: ["Use the required multiline TSDoc style."],
			signature: false,
		};
	}
	const summary = readParagraph(lines, 0);
	const remarksIndex = summary.end + 1;
	const responsibility = readParagraph(lines, remarksIndex + 1);
	const boundary = readParagraph(lines, responsibility.end + 1);
	const structure =
		lines[summary.end] === "" &&
		lines[remarksIndex] === "@remarks" &&
		responsibility.text.startsWith("Responsibility: ") &&
		lines[responsibility.end] === "" &&
		boundary.text.startsWith("Boundary: ") &&
		boundary.end === lines.length;
	if (!structure) {
		return { errors: [], signature: false };
	}
	const violations = [];
	if (!validateSummary(summary.text)) {
		violations.push("Keep the file purpose to one sentence and 25 words.");
	}
	const responsibilityText = responsibility.text.slice(
		"Responsibility: ".length,
	);
	if (
		countSentences(responsibilityText) > 2 ||
		countWords(responsibilityText) > 50
	) {
		violations.push(
			"Keep the Responsibility paragraph within two sentences and 50 words.",
		);
	}
	const boundaryText = boundary.text.slice("Boundary: ".length);
	if (countSentences(boundaryText) > 2 || countWords(boundaryText) > 50) {
		violations.push(
			"Keep the Boundary paragraph within two sentences and 50 words.",
		);
	}
	if (countWords(lines.join(" ")) > 120) {
		violations.push("Keep the complete file signature within 120 words.");
	}
	return { errors: violations, signature: true };
}

function parseMethodSignature(raw) {
	const lines = commentLines(raw);
	if (lines === null) {
		return {
			errors: ["Use the required multiline TSDoc style."],
			signature: false,
			tags: [],
		};
	}
	const summary = readParagraph(lines, 0);
	if (summary.text.length === 0) {
		return { errors: [], signature: false, tags: [] };
	}
	const violations = [];
	if (!validateSummary(summary.text)) {
		violations.push("Keep the callable summary to one sentence and 25 words.");
	}
	let index = summary.end;
	if (index < lines.length) {
		if (lines[index] !== "") {
			return {
				errors: ["Separate the summary from remarks and tags."],
				signature: true,
				tags: [],
			};
		}
		index += 1;
	}
	const foundLabels = [];
	if (lines[index] === "@remarks") {
		index += 1;
		while (index < lines.length && !lines[index].startsWith("@")) {
			if (lines[index] === "") {
				index += 1;
				continue;
			}
			const paragraph = readParagraph(lines, index);
			const match = /^([^:]+):\s+(.+)$/.exec(paragraph.text);
			if (match === null || !remarksLabels.includes(match[1])) {
				violations.push("Use only approved remarks labels.");
			} else {
				foundLabels.push(match[1]);
				if (countSentences(match[2]) > 2 || countWords(match[2]) > 50) {
					violations.push(
						`Keep the ${match[1]} paragraph within two sentences and 50 words.`,
					);
				}
			}
			index = paragraph.end;
		}
		if (foundLabels.length === 0) {
			violations.push("Add at least one labeled paragraph after @remarks.");
		}
	}
	const labelIndexes = foundLabels.map((label) => remarksLabels.indexOf(label));
	if (
		labelIndexes.some(
			(value, current) => current > 0 && value <= labelIndexes[current - 1],
		)
	) {
		violations.push("Put remarks labels in the required order.");
	}
	const tags = [];
	while (index < lines.length) {
		if (lines[index] === "") {
			index += 1;
			continue;
		}
		const match = /^@(\w+)\b(?:\s+(.*))?$/.exec(lines[index]);
		if (match === null) {
			violations.push("Use valid TSDoc tag syntax.");
			break;
		}
		let text = match[2] ?? "";
		index += 1;
		while (
			index < lines.length &&
			lines[index] !== "" &&
			!lines[index].startsWith("@")
		) {
			text += ` ${lines[index]}`;
			index += 1;
		}
		tags.push({ name: match[1], text: text.trim() });
	}
	const orders = tags.map((tag) => tagOrder.indexOf(tag.name));
	if (
		orders.some((order) => order === -1) ||
		orders.some((order, current) => current > 0 && order < orders[current - 1])
	) {
		violations.push("Use only approved tags in the required order.");
	}
	for (const tag of tags) {
		const description = ["typeParam", "param"].includes(tag.name)
			? /^\S+\s+-\s+(.+)$/.exec(tag.text)?.[1]
			: tag.text;
		if (["typeParam", "param", "returns", "throws"].includes(tag.name)) {
			if (
				description === undefined ||
				description.length === 0 ||
				countWords(description) > 30
			) {
				violations.push(
					`Keep the @${tag.name} description within 30 words and use the required syntax.`,
				);
			}
		}
	}
	if (tags.filter((tag) => tag.name === "returns").length > 1) {
		violations.push("Use at most one @returns tag.");
	}
	if (countWords(lines.join(" ")) > 200) {
		violations.push("Keep the complete callable signature within 200 words.");
	}
	return { errors: [...new Set(violations)], signature: true, tags };
}

function callableNodes(sourceFile) {
	const nodes = [];
	function visit(node) {
		const callable =
			ts.isFunctionDeclaration(node) ||
			ts.isFunctionExpression(node) ||
			ts.isArrowFunction(node) ||
			ts.isMethodDeclaration(node) ||
			ts.isConstructorDeclaration(node) ||
			ts.isGetAccessorDeclaration(node) ||
			ts.isSetAccessorDeclaration(node);
		if (callable && node.body !== undefined && ts.isBlock(node.body)) {
			nodes.push(node);
		}
		ts.forEachChild(node, visit);
	}
	visit(sourceFile);
	return nodes;
}

function parameterNames(node) {
	return node.parameters.map((parameter, index) => {
		let name = parameter.name;
		return ts.isIdentifier(name) ? name.text : `#${index + 1}`;
	});
}

function typeParameterNames(node) {
	return node.typeParameters?.map((parameter) => parameter.name.text) ?? [];
}

function returnsValue(node) {
	if (ts.isConstructorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
		return false;
	}
	if (node.type !== undefined) {
		return (
			node.type.kind !== ts.SyntaxKind.VoidKeyword &&
			node.type.kind !== ts.SyntaxKind.NeverKeyword
		);
	}
	let found = false;
	function visit(current) {
		if (found) {
			return;
		}
		if (current !== node && ts.isFunctionLike(current)) {
			return;
		}
		if (ts.isReturnStatement(current) && current.expression !== undefined) {
			found = true;
			return;
		}
		ts.forEachChild(current, visit);
	}
	visit(node.body);
	return found;
}

function immediateComment(source, comments, position) {
	const candidates = comments.filter((comment) => comment.end <= position);
	const comment = candidates.at(-1);
	return comment !== undefined &&
		source.slice(comment.end, position).trim() === ""
		? comment
		: undefined;
}

function validateFile(file) {
	const source = readFileSync(file, "utf8");
	const sourceFile = ts.createSourceFile(
		file,
		source,
		ts.ScriptTarget.Latest,
		true,
		file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
	);
	const comments = commentsIn(source, sourceFile);
	const fileSignatures = comments
		.map((comment) => ({ comment, result: parseFileSignature(comment.raw) }))
		.filter(({ result }) => result.signature);
	if (fileSignatures.length !== 1) {
		report(file, 0, "file-signature", "Add exactly one Semark file signature.");
	} else {
		const [{ comment, result }] = fileSignatures;
		const firstStatement = sourceFile.statements[0];
		const firstToken = firstStatement?.getStart(sourceFile) ?? source.length;
		const firstCallableComment =
			firstStatement !== undefined && ts.isFunctionDeclaration(firstStatement)
				? immediateComment(source, comments, firstToken)
				: undefined;
		const firstCodeBoundary =
			firstCallableComment !== undefined &&
			parseMethodSignature(firstCallableComment.raw).signature
				? firstCallableComment.start
				: firstToken;
		if (
			comment.end > firstCodeBoundary ||
			source.slice(comment.end, firstCodeBoundary).trim() !== ""
		) {
			report(
				file,
				comment.start,
				"file-signature",
				"Put the file signature before source code.",
			);
		}
		for (const message of result.errors) {
			report(file, comment.start, "file-signature", message);
		}
	}

	const authorized = new Set(
		fileSignatures.map(({ comment }) => comment.start),
	);
	for (const node of callableNodes(sourceFile)) {
		const position = node.getStart(sourceFile);
		const comment = immediateComment(source, comments, position);
		if (comment === undefined || authorized.has(comment.start)) {
			report(
				file,
				position,
				"method-signature",
				"Add a Semark signature immediately before this callable.",
			);
			continue;
		}
		const result = parseMethodSignature(comment.raw);
		if (!result.signature) {
			report(
				file,
				position,
				"method-signature",
				"Use the required Semark callable-signature structure.",
			);
			continue;
		}
		authorized.add(comment.start);
		for (const message of result.errors) {
			report(file, comment.start, "method-signature", message);
		}
		const parameters = parameterNames(node);
		const parameterTags = result.tags.filter((tag) => tag.name === "param");
		const documentedParameters = parameterTags.map(
			(tag) => /^([^\s]+)\s+-\s+/.exec(tag.text)?.[1],
		);
		const hasPattern = parameters.some((name) => name.startsWith("#"));
		if (
			parameters.length !== documentedParameters.length ||
			(!hasPattern &&
				parameters.some((name, index) => name !== documentedParameters[index]))
		) {
			report(
				file,
				comment.start,
				"method-signature",
				"Document each runtime parameter in declaration order.",
			);
		}
		const typeParameters = typeParameterNames(node);
		const documentedTypeParameters = result.tags
			.filter((tag) => tag.name === "typeParam")
			.map((tag) => /^(\S+)\s+-\s+/.exec(tag.text)?.[1]);
		if (
			typeParameters.length !== documentedTypeParameters.length ||
			typeParameters.some(
				(name, index) => name !== documentedTypeParameters[index],
			)
		) {
			report(
				file,
				comment.start,
				"method-signature",
				"Document each type parameter in declaration order.",
			);
		}
		const hasReturns = result.tags.some((tag) => tag.name === "returns");
		if (hasReturns !== returnsValue(node)) {
			report(
				file,
				comment.start,
				"method-signature",
				"Use @returns only for a callable that returns a value.",
			);
		}
	}

	for (const comment of comments) {
		if (
			!authorized.has(comment.start) &&
			!directivePatterns.some((pattern) => pattern.test(comment.raw))
		) {
			report(
				file,
				comment.start,
				"comment-policy",
				"Remove the unauthorized source comment.",
			);
		}
	}
}

function validateReadmes() {
	const packageDirectories = [repositoryRoot];
	for (const area of [
		join(repositoryRoot, "apps"),
		join(repositoryRoot, "packages"),
	]) {
		for (const entry of readdirSync(area, { withFileTypes: true })) {
			const directory = join(area, entry.name);
			if (entry.isDirectory() && existsSync(join(directory, "package.json"))) {
				packageDirectories.push(directory);
			}
		}
	}
	for (const directory of packageDirectories) {
		const names = readdirSync(directory)
			.filter((name) => name.toLowerCase() === "readme.md")
			.sort();
		if (names.length !== 1 || names[0] !== "README.md") {
			errors.push(
				`${relative(repositoryRoot, directory) || "."}:1:1 [readme-coverage] Keep exactly one README.md file in this package.`,
			);
		}
	}
}

validateReadmes();
for (const file of applicableFiles()) {
	validateFile(file);
}

if (errors.length > 0) {
	console.error(errors.join("\n"));
	console.error(
		`Semark validation found ${errors.length} violation${errors.length === 1 ? "" : "s"}.`,
	);
	process.exitCode = 1;
} else {
	console.log(
		`Semark validation passed for ${applicableFiles().length} TypeScript files.`,
	);
}
