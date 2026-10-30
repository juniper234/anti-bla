# Research and reproduction

Anti-BLA v0.1 is a bounded static companion for REA. The source inventory and controlled qualification are distinct: all 51 BLA shield files were inventoried, while recovery claims apply to the selected measured tasks in [coverage](COVERAGE.md).

## Exact research pins

| Project | Version | Source |
|---|---|---|
| BLA | 1.5.1 | [`b2d643600774d62e562081129e55b13b0d9e8a80`](https://github.com/qybaihe/bla/tree/b2d643600774d62e562081129e55b13b0d9e8a80) |
| REA | 6.8.0 | [`317bf3fe235e655b2d752d3be261cc0da7d00f2b`](https://github.com/morluto/rea/tree/317bf3fe235e655b2d752d3be261cc0da7d00f2b) |

The research inspected public implementation source and used independently authored fixtures. Known leaked upstream tests/challenge answers were excluded. The controller's source-informed qualification is not described as a blind challenge result. The separate fresh-agent trial withheld fixture answers from each worker; it was a recorded protocol on shared storage, not filesystem-enforced isolation.

## Test layers

```sh
npm ci --ignore-scripts
npm test
```

The default command builds the companion and runs **326 portable tests**. It needs no BLA/REA checkout, private report, Docker or analysis provider. It prints the names of the two excluded research suites. These 22 research tests do not count as passed or skipped.

```sh
npm run test:research
```

The opt-in research suites retain all 22 assertions. They need the exact source-built REA, a supported isolated runtime, and the original retained command/artifact streams referenced by the historical report. The runner exits with a clear prerequisite error when those inputs are absent. The original workspace ran all 348 tests; that number is distinct from the public portable suite.

## Local evidence

The public [v0.1 summary](../reports/v0.1-summary.json) records the scoped outcomes and release validation. Raw reports contain local filesystem paths, provider output and large controlled artifacts. They remain in the original development workspace and are excluded from Git and npm distributions. References to timestamped raw reports in technical guides identify those local records; they are not promised public downloads.

The public source includes the qualification harnesses and independently authored fixture helpers. Many harnesses require separately acquired tools, exact research checkouts and a supported platform; they are not production APIs. A consumer without the original evidence cannot honestly reproduce its historical hashes by running a new seed.

To perform new qualification, acquire the pinned upstream source without the excluded challenge/tests, build its documented runtime and native provider requirements, and use new owned fixtures. Record the exact seed, artifact hashes, commands, exits, limits, byte coordinates, original integrity and normal/malformed controls. Keep rejected attempts. Document new results as new experiments rather than overwriting the historical ones.

## Execution and interpretation

The shipped CLI/API/MCP parses data and never executes target imports, functions or build hooks. Controlled dynamic research fixtures ran only in disposable contained environments. Research tools and runtimes are not bundled in the npm tarball.

Worker old-generation heap settings are not total-RSS limits. Filesystem identity checks are not an OS sandbox against hostile concurrent writers. Standard-intrinsic assumptions default off, and inspection views do not establish executable equivalence.

Selected tool recovery is distinct from agent recovery. All three fresh-agent lanes completed the selected randomized tasks; no incremental agent recovery win, measured token/cost multiplier or all-shield bypass rate was established. Genuine Electron fuse settings remain real hardening. Flutter snapshot metadata is 3/3, typed labels are 2/3, and business-function/runtime recovery remains UNKNOWN. Source-map information loss and other incomplete cases stay explicit.
