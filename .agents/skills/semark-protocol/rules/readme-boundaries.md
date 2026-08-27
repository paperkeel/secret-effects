# Documentation boundaries

## Repository instructions

Use `AGENTS.md` for agent workflows, validation commands, repository conventions, and
Semark responsibilities. Do not use it as the primary architecture document.

Tell agents in `AGENTS.md` to load `semark-protocol` before they change TypeScript
comments. Prohibit source comments except Semark signatures and approved directives.
Include the configured Semark check command.

Keep `AGENTS.md` as the canonical agent instruction. Link harness-specific instruction
files to it when the repository supports links. Otherwise, add an equivalent policy to
each instruction file that the repository uses.

## Root README

Keep one `README.md` in the repository root. Define the repository purpose, major
packages, architectural boundaries, package relationships, primary commands, and
discovery entry points.

Keep it as a concise repository map. Do not put detailed package or source behavior in
it.

## Package README

Keep exactly one `README.md` in each package or application. Define the package purpose,
responsibilities, boundaries, relationships, organization, public role, and relevant
commands.

Do not add other general-purpose Markdown documents. Permit machine configuration,
contribution forms, security policy files, or generated reports only with explicit
repository approval.

## Skills

Write each skill description as a selection rule for the agent. State when the agent
must use the skill.

Write each skill body as direct instructions to the agent. Do not explain skill benefits
to a user.

Use skills for repeatable agent behavior. Do not store general codebase memory or
duplicate package architecture in a skill.
