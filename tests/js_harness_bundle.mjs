// SPDX-License-Identifier: Apache-2.0
// Minimal Node harness so tests can exercise hosted_profiles.hosted's real
// BUNDLE_JS (and MMR_JS, which it depends on for completeness-certificate
// checks) directly -- not a reimplementation of either in Python.
//
// Loaded with vm.runInThisContext (not `new Function(...)`) so top-level
// `function` declarations become real globals, exactly like a <script src>
// tag would in a browser -- `new Function(src)()` instead wraps the body in
// a private function scope and none of it would be reachable here.
//
// Reads one JSON "op" on stdin naming a pure (non-DOM) function exported by
// mmr.js/bundle.js and its arguments, calls it, awaits it if async, and
// prints the JSON result to stdout.
import { readFileSync } from "node:fs";
import vm from "node:vm";

// Minimal DOM/BOM shims -- only what bundle.js's *pure* functions touch
// transitively (none of them do; this covers the render/bootstrap tail that
// still runs once at load time, harmlessly, against these no-ops).
globalThis.window = globalThis;
globalThis.document = {
  getElementById: () => null,
  addEventListener: () => {},
  body: { appendChild: () => {}, removeChild: () => {} },
  createElement: () => ({}),
};
globalThis.location = { hash: "", pathname: "/bundle", search: "", origin: "http://verify.example", protocol: "http:" };
globalThis.history = { replaceState: () => {} };
// Node 21+ ships a partial, getter-only `navigator` global already -- no
// shim needed (nothing in the pure functions under test touches it).

const mmrSrc = readFileSync(process.argv[2], "utf8");
const bundleSrc = readFileSync(process.argv[3], "utf8");
vm.runInThisContext(mmrSrc, { filename: "mmr.js" });
vm.runInThisContext(bundleSrc, { filename: "bundle.js" });

const op = JSON.parse(readFileSync(0, "utf8"));

async function main() {
  let result;
  switch (op.fn) {
    case "decodeFragment":
      result = decodeFragment(op.hash);
      break;
    case "encodeFragment":
      result = encodeFragment(op.obj);
      break;
    case "encodeThenDecode":
      result = decodeFragment(encodeFragment(op.obj));
      break;
    case "checkCompleteness":
      result = await checkCompleteness(op.bundle);
      break;
    case "crossCheckSelfReport":
      result = await crossCheckSelfReport(op.bundle, op.records);
      break;
    case "evaluateBundleRitual":
      result = await evaluateBundleRitual(op.records, op.completeness, op.crossCheck);
      break;
    case "buildBundlePrivlog":
      result = await buildBundlePrivlog(op.records);
      break;
    case "verifyCapsuleDigests":
      result = await verifyCapsuleDigests(op.data);
      break;
    case "parseAac":
      result = parseAac(op.data);
      break;
    case "findChainGaps":
      result = findChainGaps(op.capsules);
      break;
    case "annotateRecords":
      result = annotateRecords(op.capsules);
      break;
    default:
      throw new Error("unknown fn: " + op.fn);
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((e) => {
  process.stderr.write(String((e && e.stack) || e));
  process.exit(1);
});
