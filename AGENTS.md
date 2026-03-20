<!-- @cpt:root-agents -->
## Cypilot AI Agent Navigation

**Remember these variables while working in this project:**

```toml
cypilot_path = ".cypilot"
```

## Navigation Rules

ALWAYS open and follow `{cypilot_path}/.gen/AGENTS.md` FIRST

ALWAYS open and follow `{cypilot_path}/config/AGENTS.md` FIRST

ALWAYS invoke `{cypilot_path}/.core/skills/cypilot/SKILL.md` WHEN user asks to do something with Cypilot

<!-- /@cpt:root-agents -->

These instructions are for AI assistants working in this project.

If the instruction sounds unclear, vague or requires more context. Ask for clarification.

Always open `@/guidelines/README.md` first (entry point for project-wide guidelines).

Open additional docs only when relevant:

- If the task adds/changes dependencies (Cargo.toml), introduces a new crate, involves working with 3rd-party crates (such as those for serialization/deserialization), open `@/guidelines/DEPENDENCIES.md`.

- If the task touches ModKit/module architecture (modules layout, `@/lib/modkit*`, plugins, REST wiring, ClientHub, OpenAPI, lifecycle/stateful tasks, SSE, standardized HTTP errors), open `@/docs/modkit_unified_system/README.md`.
