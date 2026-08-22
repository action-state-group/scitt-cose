// SPDX-License-Identifier: Apache-2.0
// Minimal Node harness so tests can exercise hosted_profiles.hosted's real
// CAPSULE_JS ritual functions (checkAuthenticity / evaluateRitual) directly --
// not a reimplementation of either in JS-shaped-Python. Real crypto.subtle
// Ed25519 verification runs for real here, same as it would in a browser.
//
// CAPSULE_JS's own bootstrap tail assumes a real DOM (unlike BUNDLE_JS's,
// which is guarded) so this harness slices out just the pure ritual-function
// region -- the same technique tests/js_harness_ritual_sequence.mjs uses --
// rather than shimming a full document.
//
// Reads one JSON "op" on stdin naming "checkAuthenticity" or "evaluateRitual"
// plus its arguments, calls it (always async), and prints the JSON result.
import { readFileSync } from "node:fs";

const capsuleSrc = readFileSync(process.argv[2], "utf8");
const start = capsuleSrc.indexOf("function findChainGaps(");
const end = capsuleSrc.indexOf("async function renderRitual(");
if (start < 0 || end < 0) {
  throw new Error("could not locate the ritual-function region in CAPSULE_JS");
}
const js = capsuleSrc.slice(start, end);

// Minimal stubs for helpers referenced but defined elsewhere in CAPSULE_JS
// (Integrity/graph parsing) -- irrelevant to Authenticity, which is what
// this harness exists to exercise.
const stub = `
function isH64(s){return typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);}
function unwrapEnvelope(c){return (c&&c.capsule&&typeof c.capsule==="object")?c.capsule:c;}
function sh(x){return String(x||"").slice(0,8);}
function parseAac(){return{privlog:[]};}
function _capMismatched(){return false;}
`;

const mod = await import(
  "data:text/javascript," + encodeURIComponent(stub + js + "\nexport {checkAuthenticity, evaluateRitual};")
);
const { checkAuthenticity, evaluateRitual } = mod;

const op = JSON.parse(readFileSync(0, "utf8"));

async function main() {
  let result;
  switch (op.fn) {
    case "checkAuthenticity":
      result = await checkAuthenticity(op.capsules);
      break;
    case "evaluateRitual":
      result = await evaluateRitual(op.capsules, op.witness ?? null, op.integrity ?? null);
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
