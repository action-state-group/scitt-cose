// SPDX-License-Identifier: Apache-2.0
// Runs the bundle page's own script set, in page order, as the browser would
// (one global scope), then calls one function: so a test exercises what the
// page loads, not a hand-picked set of files.
//
// argv: a JSON file listing the script files in page order. stdin: one op.
import { readFileSync } from "node:fs";
import vm from "node:vm";

globalThis.window = globalThis;
globalThis.document = {
  getElementById: () => null,
  addEventListener: () => {},
  body: { appendChild: () => {}, removeChild: () => {} },
  createElement: () => ({}),
};
globalThis.location = { hash: "", pathname: "/bundle", search: "", origin: "http://verify.example", protocol: "http:" };
globalThis.history = { replaceState: () => {} };

for (const path of JSON.parse(readFileSync(process.argv[2], "utf8"))) {
  vm.runInThisContext(readFileSync(path, "utf8"), { filename: path });
}

const op = JSON.parse(readFileSync(0, "utf8"));
async function main() {
  let result;
  switch (op.fn) {
    case "checkCompleteness":
      result = await checkCompleteness(op.bundle);
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
