# Documentation

| Where | What |
|---|---|
| [architecture/](./architecture/README.md) | The design narrative, in reading order — start here. Problem → data structures → classification → trie → scenarios → billing → contracts, plus the concept primer |
| [adr/](./adr/README.md) | Architecture Decision Records — every considered-and-rejected alternative with its reasoning |
| [development/](./development/) | Contributor-facing: [testing.md](./development/testing.md) (the four test tiers and CI gates) and [conventions.md](./development/conventions.md) (constructor idioms, package anatomy, hot-path rules) |
| [operations/](./operations/) | Operator-facing: [runtime.md](./operations/runtime.md) (SIGHUP reload, hot-tunable knobs, /debug endpoints) |
| [sprint-plan.md](./sprint-plan.md) | Historical planning record (references the pre-restructure design-doc numbering) |

Code comments reference these pages as `docs/<group>/<file>.md#<heading-anchor>`;
a guard test in the repo verifies every such reference resolves, so a heading
rename without updating its citations fails CI.
