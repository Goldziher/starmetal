---
priority: high
---

# Basemind MCP

- Keep Basemind configured as an ai-rulez plugin through `[[plugins]]`; do not add Basemind as a raw `mcp_server`.
- Configure the ai-rulez MCP server with `npx -y ai-rulez@latest mcp` so agents can manage `.ai-rulez/` safely.
- Edit ai-rulez source files first, then regenerate outputs with `npx -y ai-rulez@latest generate --gitignore`.
- When Basemind MCP tools are available, prefer them for code navigation and repository context before falling back to shell tools:
  `outline`, `search_symbols`, `find_references`, `find_callers`, and `workspace_grep` for code search;
  `recent_changes`, `blame_file`, `blame_symbol`, `diff_file`, `diff_outline`, and `commits_touching` for git history;
  `search_documents`, `web_scrape`, `web_crawl`, and `web_map` for docs and web retrieval.
- Use shell, `rg`, and raw `git` when Basemind is unavailable, when exact raw output is required, or when a task runner/check is the source of truth.
