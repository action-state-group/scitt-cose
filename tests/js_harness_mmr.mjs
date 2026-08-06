// SPDX-License-Identifier: Apache-2.0
// Minimal Node harness so tests can exercise hosted_profiles.hosted's real
// MMR_JS directly (not a reimplementation of it in Python) -- reads one JSON
// "op" describing which MMR function to call and with what arguments on
// stdin, evaluates mmr.js in this process, calls the requested function, and
// prints the JSON result to stdout.
import { readFileSync } from "node:fs";

const src = readFileSync(process.argv[2], "utf8");
new Function(src)();

const op = JSON.parse(readFileSync(0, "utf8"));

async function main() {
  const MMR = globalThis.MMR;
  let result;
  if (op.fn === "interiorHash") {
    const h = await MMR.interiorHash(MMR.hexToBytes(op.left), MMR.hexToBytes(op.right), op.position);
    result = MMR.bytesToHex(h);
  } else if (op.fn === "rootFromPeaks") {
    const peaks = op.peaks.map(MMR.hexToBytes);
    const h = await MMR.rootFromPeaks(peaks);
    result = MMR.bytesToHex(h);
  } else if (op.fn === "peaks") {
    result = MMR.peaks(op.size);
  } else if (op.fn === "verifyInclusion") {
    result = await MMR.verifyInclusion(op.root, op.size, op.leaf_index, op.body_digest, op.proof);
  } else if (op.fn === "verifyConsistency") {
    result = await MMR.verifyConsistency(op.root_a, op.size_a, op.root_b, op.size_b, op.proof);
  } else {
    throw new Error("unknown fn: " + op.fn);
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((e) => {
  process.stderr.write(String((e && e.stack) || e));
  process.exit(1);
});
