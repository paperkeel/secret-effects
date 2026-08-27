# Secret Effects CLI

This application supplies the `secreteffects` command interface and terminal
interface. It issues credentials, publishes schemas and encrypted bundles, reads
environments, and operates service resources.

The application reads local credential material and sends signed requests to the
API. It delegates configuration, cryptography, and wire schemas to workspace
packages.

## Organization

- `src/bin.ts` implements noninteractive commands.
- `src/tui.tsx` implements the terminal interface.

Run `pnpm --filter @secret-effects/cli build` to build the executable bundle.
