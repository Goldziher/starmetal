# Contributing

## AI governance

Install [mise](https://mise.jdx.dev/), run `mise install`, then run `mise run governance:hooks`.
Tasks, hooks and CI all run the latest ai-rulez release (`npx -y ai-rulez@latest`).

Edit `.ai-rulez/` sources, then run `ai-rulez migrate okf --check`,
`ai-rulez validate --strict --no-local`, `ai-rulez lock --content-only`, and
`ai-rulez generate --no-local --strict-config`. Verify generated freshness with
`ai-rulez generate --no-local --strict-config --check` and `ai-rulez lock --check`.
