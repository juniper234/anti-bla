import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { inspectNative } from "../dist/native.js";
import { protectNativeBinary } from "../research/bla/dist/shields/formats/native.js";
import { pe, elf, macho } from "../test/helpers/native-fixtures.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), ".."),
  runId = new Date().toISOString().replace(/[:.]/g, "-"),
  out = resolve(root, "scratch/native/runs", runId),
  reportPath = resolve(root, `reports/C5-native-core-${runId}.json`);
await mkdir(out, { recursive: true });
await mkdir(resolve(root, "scratch/native/go-temp"), { recursive: true });
const node = resolve(root, ".runtime/node-v24.22.1-win-x64/node.exe"),
  rea = resolve(root, "research/rea/scripts/rea.mjs"),
  go = "C:/Program Files/Go/bin/go.exe";
const hash = (b) => createHash("sha256").update(b).digest("hex");
const report = {
  schema: "anti-bla.native-qualification/1",
  startedAt: new Date().toISOString(),
  status: "CONDITIONAL",
  audit_source: "self",
  sourcePins: {
    bla: "b2d643600774d62e562081129e55b13b0d9e8a80",
    rea: "317bf3fe235e655b2d752d3be261cc0da7d00f2b",
  },
  task: "Read own score business function as code; inspect actual Go build metadata separately",
  targetExecution: false,
  measurements: {
    wall: "performance.now monotonic milliseconds",
    providerPeakMemory: null,
    providerCpu: null,
    reason: "provider process tree resources not measured; no estimates",
  },
  runs: [],
  frameworks: [],
  limitations: [],
};
async function command(id, executable, args, env = {}) {
  const start = performance.now();
  let stdout = [],
    stderr = [],
    timedOut = false;
  const child = spawn(executable, args, {
    cwd: root,
    env: { ...process.env, ...env },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let size = 0;
  child.stdout.on("data", (x) => {
    size += x.length;
    if (size < 8 * 1024 * 1024) stdout.push(x);
    else child.kill();
  });
  child.stderr.on("data", (x) => {
    if (stderr.reduce((n, b) => n + b.length, 0) < 1024 * 1024) stderr.push(x);
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, 180000);
  const exit = await new Promise((resolve) => {
    child.on("error", (e) => {
      stderr.push(Buffer.from(String(e)));
      resolve(null);
    });
    child.on("close", resolve);
  });
  clearTimeout(timeout);
  const a = Buffer.concat(stdout),
    b = Buffer.concat(stderr),
    stdoutPath = resolve(out, `${id}.stdout.json`),
    stderrPath = resolve(out, `${id}.stderr.log`);
  await writeFile(stdoutPath, a);
  await writeFile(stderrPath, b);
  let parsed = null;
  try {
    parsed = JSON.parse(a.toString());
  } catch {}
  const record = {
    command: [executable, ...args],
    exitCode: exit,
    timedOut,
    wallMs: Math.round((performance.now() - start) * 1000) / 1000,
    stdoutPath,
    stdoutSha256: hash(a),
    stderrPath,
    stderrSha256: hash(b),
    stdoutBytes: a.length,
    stderrBytes: b.length,
    peakMemoryBytes: null,
    cpuSeconds: null,
    targetExecuted: false,
  };
  return { record, parsed, text: a.toString() };
}
async function reaCall(id, operation, path, args = []) {
  return command(id, node, [rea, operation, path, ...args, "--format", "json"]);
}
const provider = await command("source-rea-version", node, [rea, "--version"]);
report.sourceReaVersion = provider.text.trim();
report.versionCommand = provider.record;
for (const [index, multiplier, addend] of [
  [1, 3, 7],
  [2, 5, 11],
  [3, 7, 13],
]) {
  const seed = `native-own-${index}-20261030`,
    clean = pe({ multiplier, addend }),
    cleanPath = resolve(out, `own-${index}.exe`),
    protectedPath = resolve(out, `own-${index}.protected.exe`);
  await writeFile(cleanPath, clean);
  const emitterStart = performance.now(),
    emitted = protectNativeBinary(clean, { seed, intensity: "maximum" }),
    protectedBytes = emitted.buffer,
    emitterWallMs = performance.now() - emitterStart;
  await writeFile(protectedPath, protectedBytes);
  const { buffer, ...emitter } = emitted;
  const sidecarStart = performance.now(),
    before = inspectNative(clean, { limit: 100 }),
    after = inspectNative(protectedBytes, { limit: 100 }),
    sidecarMs = performance.now() - sidecarStart;
  await writeFile(
    resolve(out, `own-${index}.layout.json`),
    JSON.stringify({ before, after }, null, 2),
  );
  const baseline = await reaCall(`pe-${index}-clean`, "decompile", cleanPath, [
    "--procedure",
    "score",
    "--provider",
    "ghidra",
  ]);
  const protectedBaseline = await reaCall(
    `pe-${index}-protected`,
    "decompile",
    protectedPath,
    ["--procedure", "score", "--provider", "ghidra"],
  );
  const entry = after.entrypoint;
  const anti =
    entry?.status === "ok"
      ? await reaCall(`pe-${index}-anti`, "decompile", protectedPath, [
          "--file-offset",
          "0x" + entry.fileOffset.toString(16),
          "--provider",
          "ghidra",
        ])
      : null;
  const found = (r) => {
    if (
      r?.record.exitCode !== 0 ||
      typeof r.parsed?.normalized_result !== "string"
    )
      return false;
    const match =
      /return\s+param_1\s*\*\s*(0x[0-9a-f]+|\d+)\s*\+\s*(0x[0-9a-f]+|\d+)\s*;/i.exec(
        r.parsed.normalized_result,
      );
    return (
      !!match && Number(match[1]) === multiplier && Number(match[2]) === addend
    );
  };
  const cleanFuses = await reaCall(
      `pe-${index}-clean-fuses`,
      "inspect-electron-fuses",
      cleanPath,
    ),
    protectedFuses = await reaCall(
      `pe-${index}-protected-fuses`,
      "inspect-electron-fuses",
      protectedPath,
    );
  report.runs.push({
    fixture: index,
    origin:
      "independently authored literal PE headers/export plus x64 machine code, test/helpers/native-fixtures.mjs; not a real Rust/Go/Flutter/Electron app",
    seed,
    intensity: "maximum",
    expectedTask: {
      symbol: "score",
      entryFileOffset: 512,
      expression: `int32(value) * ${multiplier} + ${addend}`,
      machineCode: clean.subarray(512, 519).toString("hex"),
    },
    sourceSha256: hash(
      await readFile(resolve(root, "test/helpers/native-fixtures.mjs")),
    ),
    clean: { path: cleanPath, sha256: hash(clean), size: clean.length },
    protected: {
      path: protectedPath,
      sha256: hash(protectedBytes),
      size: protectedBytes.length,
    },
    emitter: {
      entrypoint: "actual pinned BLA protectNativeBinary",
      ...emitter,
      wallMs: emitterWallMs,
    },
    sidecar: {
      wallMs: sidecarMs,
      beforeStatus: before.status,
      afterStatus: after.status,
      entrypoint: entry,
      mappedExecutableRangesBefore: before.executableRanges,
      mappedExecutableRangesAfter: after.executableRanges,
      byteIdenticalExecutableRanges:
        JSON.stringify(before.executableRanges) ===
        JSON.stringify(after.executableRanges),
      originalPrefixPreserved: protectedBytes
        .subarray(0, clean.length)
        .equals(clean),
    },
    providerControls: {
      clean: baseline.record,
      protected: protectedBaseline.record,
      anti: anti?.record ?? null,
    },
    taskRecovered: {
      clean: found(baseline),
      protected: found(protectedBaseline),
      anti: found(anti),
    },
    fuseMetadataControls: {
      clean: cleanFuses.record,
      protected: protectedFuses.record,
      cleanResult: cleanFuses.parsed,
      protectedResult: protectedFuses.parsed,
    },
    verdict:
      found(baseline) && found(protectedBaseline) && found(anti)
        ? "CONTROLLED_STATIC_RECOVERY; baseline also succeeds, no incremental bypass demonstrated"
        : "UNKNOWN",
  });
  await writeFile(
    reportPath,
    JSON.stringify(report, null, 2),
  );
  console.log(
    JSON.stringify({ fixture: index, task: report.runs.at(-1).taskRecovered }),
  );
}
// Real Go compiler outputs: compilation only, no generated target runs on host.
for (const [index, multiplier, addend] of [
  [1, 3, 7],
  [2, 5, 11],
  [3, 7, 13],
]) {
  const source = `package main\nvar Sink int\n//go:noinline\nfunc score(value int) int { return value * ${multiplier} + ${addend} }\nfunc main() { Sink = score(${index + 10}) }\n`,
    sourcePath = resolve(out, `go-own-${index}.go`),
    cleanPath = resolve(out, `go-own-${index}.elf`),
    protectedPath = resolve(out, `go-own-${index}.protected.elf`);
  await writeFile(sourcePath, source);
  const build = await command(
    `go-${index}-compile`,
    go,
    ["build", "-trimpath", "-ldflags=-buildid=", "-o", cleanPath, sourcePath],
    {
      GOOS: "linux",
      GOARCH: "amd64",
      CGO_ENABLED: "0",
      GOTOOLCHAIN: "local",
      GOCACHE: resolve(root, "scratch/native/go-cache"),
      GOTMPDIR: resolve(root, "scratch/native/go-temp"),
    },
  );
  if (build.record.exitCode !== 0) {
    report.frameworks.push({
      framework: "Go",
      fixture: index,
      status: "UNKNOWN",
      build: build.record,
    });
    continue;
  }
  const clean = await readFile(cleanPath),
    emitted = protectNativeBinary(clean, {
      seed: `go-own-${index}`,
      intensity: "maximum",
    }),
    protectedBytes = emitted.buffer;
  await writeFile(protectedPath, protectedBytes);
  const before = inspectNative(clean, { limit: 100 }),
    after = inspectNative(protectedBytes, { limit: 100 });
  await writeFile(
    resolve(out, `go-${index}.layout.json`),
    JSON.stringify({ before, after }, null, 2),
  );
  const baseline = await reaCall(
      `go-${index}-clean`,
      "inspect-go-binary",
      cleanPath,
    ),
    protectedBaseline = await reaCall(
      `go-${index}-protected`,
      "inspect-go-binary",
      protectedPath,
    );
  report.frameworks.push({
    framework: "Go",
    fixture: index,
    status: "STATIC_LAYOUT_ONLY; original overwritten metadata unrecovered",
    toolchain: "actual installed Go (version captured separately)",
    sourcePath,
    sourceSha256: hash(Buffer.from(source)),
    build: build.record,
    seed: `go-own-${index}`,
    intensity: "maximum",
    clean: { path: cleanPath, sha256: hash(clean) },
    protected: { path: protectedPath, sha256: hash(protectedBytes) },
    mappedGoBuildInfoPlanted: emitted.mappedGoBuildInfoPlanted,
    beforeStatus: before.status,
    afterStatus: after.status,
    byteIdenticalExecutableRanges:
      JSON.stringify(before.executableRanges) ===
      JSON.stringify(after.executableRanges),
    metadataChanged: !protectedBytes.subarray(0, clean.length).equals(clean),
    reaClean: baseline.record,
    reaProtected: protectedBaseline.record,
    metadataRecovery: "UNKNOWN; original metadata not reconstructed",
    businessFunctionRecovery:
      "UNKNOWN; Windows REA native provider does not admit ELF",
    layout: resolve(out, `go-${index}.layout.json`),
  });
  await writeFile(
    reportPath,
    JSON.stringify(report, null, 2),
  );
  console.log(
    JSON.stringify({
      goFixture: index,
      layout: after.status,
      mappedMetadataMutation: emitted.mappedGoBuildInfoPlanted,
    }),
  );
}
report.goVersion = (await command("go-version", go, ["version"])).text.trim();
for (const [name, make] of [
  ["synthetic-ELF", elf],
  ["synthetic-MachO", macho],
]) {
  const b = make();
  report.frameworks.push({
    framework: name,
    toolchainIdentity: "synthetic format carrier, not a genuine framework app",
    status: inspectNative(b).status,
    sha256: hash(b),
  });
}
report.limitations = [
  "Self-reviewed white-box qualification; no blind artifact-only reviewer, no C5 PASS.",
  "Only independently owned fixture data was inspected; targets never executed.",
  "Successful baseline decompilation means these runs demonstrate static code recovery beyond bait, not an incremental bypass.",
  "Mapped executable byte identity is not full behavior/signature equivalence.",
  "Go buildinfo mutations destroy original metadata; no recovery of original metadata asserted.",
  "Rust, Bun and Flutter genuine artifacts require separately recorded compiler/artifact acquisition; synthetic carriers do not fill those gaps.",
  "Windows source REA native P0 does not admit general ELF/Mach-O code decompilation.",
  "Provider CPU and peak memory remain null because unmeasured.",
];
report.completedAt = new Date().toISOString();
await writeFile(
  reportPath,
  JSON.stringify(report, null, 2),
);
console.log("qualification recorded; verdict CONDITIONAL");
