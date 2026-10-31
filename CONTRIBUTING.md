# Contributing

## AI governance

Install [mise](https://mise.jdx.dev/), run `mise install`, then run `mise run governance:hooks`.
Installing governance hooks requires Python 3.11 or newer. CI uses the reviewed
5.3.0 source revision `1dd46d774f156f3d170ecd1b702598b12d1eaf5b`.

Edit `.ai-rulez/` sources, then run `ai-rulez migrate okf --check`,
`ai-rulez validate --strict --no-local`, `ai-rulez lock --content-only`, and
`ai-rulez generate --no-local --strict-config`. Verify generated freshness with
`ai-rulez generate --no-local --strict-config --check` and `ai-rulez lock --check`.
