// Witness evidence in an Evidence Bundle, checked in the reader's browser.
//
// A bundle may say that a witness holds its checkpoint: a receipt on the
// bundle's own checkpoint (checkpoint.witnesses), or a chain through a
// cadence log (extensions["cadence-witness/v0"]): the bundle's checkpoint
// is a salted leaf of a tree whose root is an entry of a cadence log, and
// the cadence checkpoint carries the receipts. This module checks that
// evidence the way the reference CLI does (capsulectl verify --bundle
// --witness-directory), and says which parts it checked and which it only
// found present:
//
//   - the checkpoint's COSE signature (the CLL checkpoint profile: tagged
//     COSE_Sign1, EdDSA, kid = the raw Ed25519 key, CWT iss = log id and
//     sub = "<iss>#<size>", canonical CBOR claims);
//   - each receipt: an RFC 9162 COSE receipt over the checkpoint's entry
//     hash, verified under the key the READER's witness list names for that
//     witness. No list, or no row for the witness: "present, not checked";
//   - the cadence chain: the leaf, the 16-step path, the cadence entry's MMR
//     inclusion, the cadence checkpoint (same signing key), its receipts;
//   - "in part": an earlier checkpoint of the same log, signed by the same
//     key, that the bundle's checkpoint extends (an MMR consistency proof).
//
// Nothing is fetched. MMR inclusion and consistency are the page's own MMR
// verifier (injected), the same one the range checks use.

import { decode, encode, rfc8949EncodeOptions } from "cborg";

const CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor";
const CADENCE_EXTENSION = "cadence-witness/v0";
const CADENCE_DEPTH = 16;
const ED25519_SPKI_PREFIX = "302a300506032b6570032100";

const enc = new TextEncoder();
const canonicalCbor = (value) => encode(value, rfc8949EncodeOptions);
const cborOptions = { allowIndefinite: false, coerceUndefinedToNull: false, useMaps: true };

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("not hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function b64Decode(s, urlSafe) {
  if (typeof s !== "string") throw new Error("not base64");
  let t = s.trim();
  if (urlSafe) t = t.replace(/-/g, "+").replace(/_/g, "/");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function ed25519Verify(key32, message, signature) {
  try {
    const key = await crypto.subtle.importKey("raw", key32, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, message);
  } catch (e) {
    return false;
  }
}
const sigStructure = (protectedBstr, payload) => canonicalCbor(["Signature1", protectedBstr, new Uint8Array(), payload]);

// RFC3339 time as Go's RFC3339Nano renders it in UTC: trailing zeros of the
// fraction dropped, "Z".
function goRFC3339Nano(value) {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(value);
  if (!m) throw new Error("issued_at is not RFC 3339");
  const fraction = (m[2] || "").padEnd(9, "0");
  const parsed = new Date(`${m[1]}.${fraction.slice(0, 3)}${m[3]}`);
  if (Number.isNaN(parsed.valueOf())) throw new Error("issued_at is not a time");
  const trimmed = fraction.replace(/0+$/, "");
  return `${parsed.toISOString().slice(0, 19)}${trimmed === "" ? "" : "." + trimmed}Z`;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("canonical JSON takes safe integers only");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}

function decodePeaks(value) {
  if (!(value instanceof Uint8Array)) return undefined;
  const peaks = decode(value, { allowIndefinite: false, coerceUndefinedToNull: false });
  if (!Array.isArray(peaks) || peaks.some((p) => !(p instanceof Uint8Array) || p.length !== 32)) return undefined;
  if (!bytesEqual(canonicalCbor(peaks), value)) return undefined;
  return peaks;
}

/** Verify a signed CLL checkpoint (COSE_Sign1). Returns its signed fields,
 * or { ok: false, reason }. The key is the one the checkpoint names (kid):
 * this shows who signed it, not that the signer is trusted. */
export async function verifyCheckpoint(cose, mmr) {
  const fail = (reason) => ({ ok: false, reason });
  try {
    if (!(cose instanceof Uint8Array) || cose.length < 2 || cose[0] !== 0xd2 || cose[1] !== 0x84) return fail("not a tagged COSE_Sign1");
    const items = decode(cose.subarray(1), cborOptions);
    if (!Array.isArray(items) || items.length !== 4 || !(items[0] instanceof Uint8Array) || !(items[1] instanceof Map) || items[1].size !== 0 || !(items[2] instanceof Uint8Array) || !(items[3] instanceof Uint8Array)) return fail("malformed COSE_Sign1");
    if (!bytesEqual(concat(Uint8Array.of(0xd2), canonicalCbor(items)), cose)) return fail("not canonical CBOR");
    const headers = decode(items[0], cborOptions);
    if (!(headers instanceof Map)) return fail("malformed protected header");
    const kid = headers.get(4);
    const cwt = headers.get(15);
    if (headers.size !== 4 || headers.get(1) !== -8 || headers.get(3) !== CHECKPOINT_CONTENT_TYPE || !(kid instanceof Uint8Array) || kid.length !== 32 || !(cwt instanceof Map) || cwt.size !== 2) return fail("not the checkpoint profile's protected header");
    const logId = cwt.get(1);
    const subject = cwt.get(2);
    if (typeof logId !== "string" || typeof subject !== "string") return fail("malformed CWT claims");
    const claims = decode(items[2], cborOptions);
    if (!(claims instanceof Map) || !bytesEqual(canonicalCbor(claims), items[2])) return fail("claims are not canonical CBOR");
    const allowed = new Set(["kind", "log_size", "commitment", "prev_size", "prev_commitment", "issued_at", "cadence", "consistency_proof"]);
    if (claims.size < 6 || [...claims.keys()].some((k) => typeof k !== "string" || !allowed.has(k)) || claims.get("kind") !== "cll-checkpoint") return fail("not a CLL checkpoint");
    const size = claims.get("log_size");
    const prevSize = claims.get("prev_size");
    const issuedAt = claims.get("issued_at");
    if (!Number.isSafeInteger(size) || size < 1 || !Number.isSafeInteger(prevSize) || prevSize < 0 || prevSize >= size || typeof issuedAt !== "string") return fail("malformed sizes or time");
    if (subject !== `${logId}#${size}`) return fail("CWT subject does not name this log and size");
    const peaks = decodePeaks(claims.get("commitment"));
    if (!peaks || peaks.length !== mmr.peaks(size).length) return fail("malformed commitment");
    const prevCommitment = claims.get("prev_commitment");
    if (!(prevCommitment instanceof Uint8Array)) return fail("malformed previous commitment");
    let prevPeaks = [];
    if (prevSize === 0) {
      if (prevCommitment.length !== 0 || claims.has("consistency_proof")) return fail("a first checkpoint carries no previous commitment");
    } else {
      prevPeaks = decodePeaks(prevCommitment);
      const proof = claims.get("consistency_proof");
      if (!prevPeaks || !(proof instanceof Map)) return fail("missing consistency proof");
      const wire = {
        v: 1, kind: "consistency", size_a: proof.get("size_a"), size_b: proof.get("size_b"),
        old_peaks: (proof.get("old_peaks") || []).map(bytesToHex),
        witness: (proof.get("witness") || []).map((w) => (Array.isArray(w) ? w.map(bytesToHex) : w)),
        new_peaks: (proof.get("new_peaks") || []).map(bytesToHex),
      };
      const oldRoot = bytesToHex(await mmr.rootFromPeaks(prevPeaks));
      const newRoot = bytesToHex(await mmr.rootFromPeaks(peaks));
      if (proof.size !== 5 || wire.size_a !== prevSize || wire.size_b !== size || !(await mmr.verifyConsistency(oldRoot, prevSize, newRoot, size, wire))) return fail("the checkpoint does not extend its previous one");
    }
    if (!(await ed25519Verify(kid, sigStructure(items[0], items[2]), items[3]))) return fail("signature does not verify under the key the checkpoint names");
    return {
      ok: true, logId, size, peaks, prevSize, prevPeaks, issuedAt,
      kid: bytesToHex(kid),
      root: bytesToHex(await mmr.rootFromPeaks(peaks)),
      prevRoot: prevSize === 0 ? "" : bytesToHex(await mmr.rootFromPeaks(prevPeaks)),
    };
  } catch (e) {
    return fail("malformed: " + (e && e.message ? e.message : e));
  }
}

/** The RFC 9162 entry a witness logs for a checkpoint: SHA-256 of SHA-256 of
 * its canonical JSON projection. */
export async function checkpointEntryHash(cp) {
  const projection = {
    v: 1, kind: "mmr_checkpoint", log_id: cp.logId, mmr_size: cp.size, root: cp.root,
    prev_size: cp.prevSize, prev_root: cp.prevRoot, key_id: cp.kid, timestamp: goRFC3339Nano(cp.issuedAt),
  };
  return sha256(await sha256(enc.encode(canonicalJson(projection))));
}

function largestPowerBelow(n) {
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}
function expectedPath(size, index) {
  let count = 0, nodes = size, position = index;
  while (nodes > 1) {
    count++;
    const split = largestPowerBelow(nodes);
    if (position < split) nodes = split;
    else {
      nodes -= split;
      position -= split;
    }
  }
  return count;
}
async function receiptRoot(entry, index, size, path) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size || path.length !== expectedPath(size, index)) return undefined;
  const siblings = [...path];
  const leaf = await sha256(concat(Uint8Array.of(0), entry));
  const fold = async (nodes, position) => {
    if (nodes === 1) return leaf;
    const sibling = siblings.pop();
    if (sibling === undefined) return undefined;
    const split = largestPowerBelow(nodes);
    if (position < split) {
      const child = await fold(split, position);
      return child === undefined ? undefined : sha256(concat(Uint8Array.of(1), child, sibling));
    }
    const child = await fold(nodes - split, position - split);
    return child === undefined ? undefined : sha256(concat(Uint8Array.of(1), sibling, child));
  };
  const root = await fold(size, index);
  return root !== undefined && siblings.length === 0 ? root : undefined;
}

/** Verify an RFC 9162 COSE receipt for entry under one Ed25519 key. */
export async function verifyReceipt(entry, receiptBytes, leafIndex, treeSize, key32) {
  try {
    if (receiptBytes.length < 2 || receiptBytes[0] !== 0xd2) return false;
    const items = decode(receiptBytes.subarray(1), cborOptions);
    if (!Array.isArray(items) || items.length !== 4 || !(items[0] instanceof Uint8Array) || !(items[1] instanceof Map) || !(items[3] instanceof Uint8Array)) return false;
    const headers = decode(items[0], cborOptions);
    if (!(headers instanceof Map) || headers.get(1) !== -8 || headers.get(395) !== 1) return false;
    const vdp = items[1].get(396);
    if (!(vdp instanceof Map)) return false;
    const proofs = vdp.get(-1);
    if (!Array.isArray(proofs) || proofs.length !== 1 || !(proofs[0] instanceof Uint8Array)) return false;
    const proof = decode(proofs[0], { allowIndefinite: false });
    if (!Array.isArray(proof) || proof.length !== 3 || proof[0] !== treeSize || proof[1] !== leafIndex || !Array.isArray(proof[2]) || proof[2].some((h) => !(h instanceof Uint8Array) || h.length !== 32)) return false;
    const root = await receiptRoot(entry, leafIndex, treeSize, proof[2]);
    if (!root) return false;
    return ed25519Verify(key32, sigStructure(items[0], root), items[3]);
  } catch (e) {
    return false;
  }
}

/** Read a witness list the reader chose: {"witnesses":[...]} or a bare
 * array of rows {name, endpoint, binding?, key_ids, public_keys?}. */
export function parseWitnessList(text) {
  const doc = JSON.parse(text);
  const rows = Array.isArray(doc) ? doc : doc && Array.isArray(doc.witnesses) ? doc.witnesses : null;
  if (!rows) throw new Error('a witness list is {"witnesses": [...]} or an array of rows');
  return rows.filter((r) => r && typeof r === "object");
}

function witnessBinding(url) {
  const i = url.indexOf("://");
  if (i < 0) return "cll";
  const scheme = url.slice(0, i).toLowerCase();
  for (const b of ["rekor", "scrapi"]) if (scheme.startsWith(b + "+")) return b;
  return "cll";
}
function witnessEndpoint(url) {
  let u = url;
  if (witnessBinding(u) !== "cll") u = u.slice(u.indexOf("+") + 1);
  return u.replace(/\/+$/, "");
}
async function rowKeys(row) {
  const byHash = new Map();
  for (const b64 of Array.isArray(row.public_keys) ? row.public_keys : []) {
    try {
      const der = b64Decode(b64, false);
      if (der.length === 44 && bytesToHex(der.subarray(0, 12)) === ED25519_SPKI_PREFIX) byHash.set(bytesToHex(await sha256(der)), der.subarray(12));
    } catch (e) {
      // not a key this list can use
    }
  }
  const keys = [];
  for (const id of Array.isArray(row.key_ids) ? row.key_ids : []) {
    if (byHash.has(id)) keys.push(byHash.get(id));
    else if (typeof id === "string" && /^[0-9a-f]{64}$/.test(id)) keys.push(hexToBytes(id));
  }
  return keys;
}

const asInt = (v) => (typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v);

/** Check the receipts carried for a verified checkpoint, against the
 * reader's witness list (null: none chosen). Per receipt: pass, fail, or
 * withheld ("present, not checked") with the reason. */
export async function checkReceipts(cp, entries, list) {
  const out = [];
  const entry = await checkpointEntryHash(cp);
  for (const e of entries || []) {
    const url = e && typeof e.ts_url === "string" ? e.ts_url : "";
    const r = { witness: url, status: "withheld", reason: "" };
    out.push(r);
    try {
      if (bytesToHex(entry) !== e.entry_hash) {
        r.status = "fail";
        r.reason = "the receipt is for a different checkpoint";
        continue;
      }
      if (!list) {
        r.reason = "present, not checked: choose a witness list to check it";
        continue;
      }
      const binding = witnessBinding(url), endpoint = witnessEndpoint(url);
      const row = list.find((w) => (w.binding || "cll") === binding && typeof w.endpoint === "string" && w.endpoint.replace(/\/+$/, "") === endpoint);
      if (!row) {
        r.reason = "present, not checked: your witness list has no entry for this witness";
        continue;
      }
      if (binding !== "cll") {
        r.reason = "present, not checked: this page checks cll receipts only, not " + binding;
        continue;
      }
      const keys = await rowKeys(row);
      if (!keys.length) {
        r.reason = "present, not checked: your witness list names no usable key for this witness";
        continue;
      }
      const bytes = b64Decode(e.receipt_b64, false);
      let ok = false;
      for (const key of keys) if (await verifyReceipt(entry, bytes, asInt(e.leaf_index), asInt(e.tree_size), key)) ok = true;
      r.status = ok ? "pass" : "fail";
      r.reason = ok ? "verified under " + (row.name || endpoint) + "'s key from your witness list" : "does not verify under the key your witness list names";
    } catch (err) {
      r.status = "fail";
      r.reason = "malformed receipt";
    }
  }
  return out;
}

function overall(receipts) {
  if (receipts.some((r) => r.status === "fail")) return "fail";
  if (receipts.some((r) => r.status === "pass")) return "pass";
  return "withheld";
}

async function cadenceLeaf(logId, size, checkpointSha256, salt) {
  const body = canonicalJson({ checkpoint_sha256: checkpointSha256, log_id: logId, salt, size });
  return sha256(concat(Uint8Array.of(0), enc.encode(body)));
}

/** Check a bundle's witness evidence. mmr is the page's MMR verifier; list
 * is the reader's witness list (parsed rows) or null.
 *
 * Returns { checkpoint: {status, reason, logId, size, kid},
 *           rung: "witnessed" | "witnessed_in_part" | null,
 *           stepsWitnessed, steps (in part only),
 *           chain: {status, reason} | null,
 *           receipts: [{witness, status, reason}],
 *           status: "pass" | "fail" | "withheld" | "absent" }
 * rung is set only when this page verified a receipt itself. */
export async function checkWitnessEvidence(bundle, mmr, list) {
  const out = { checkpoint: { status: "withheld", reason: "the bundle carries no signed checkpoint" }, rung: null, chain: null, receipts: [], status: "absent" };
  const stated = bundle && bundle.checkpoint;
  if (!stated || typeof stated.cose !== "string") return out;
  let cose;
  try {
    cose = b64Decode(stated.cose, true);
  } catch (e) {
    out.checkpoint = { status: "fail", reason: "the signed checkpoint is not base64url" };
    out.status = "fail";
    return out;
  }
  const cp = await verifyCheckpoint(cose, mmr);
  if (!cp.ok) {
    out.checkpoint = { status: "fail", reason: cp.reason };
    out.status = "fail";
    return out;
  }
  const mismatch = ["log_id", "mmr_size", "root"].find((k) => stated[k] !== undefined && String(stated[k]) !== String({ log_id: cp.logId, mmr_size: cp.size, root: cp.root }[k]));
  if (mismatch) {
    out.checkpoint = { status: "fail", reason: "the bundle's copy of " + mismatch + " differs from the signed checkpoint" };
    out.status = "fail";
    return out;
  }
  out.checkpoint = { status: "pass", reason: "signature verifies under the key the checkpoint names", logId: cp.logId, size: cp.size, kid: cp.kid };

  const chain = bundle.extensions && bundle.extensions[CADENCE_EXTENSION];
  if (chain && chain.state === "witnessed") return checkCadence(out, chain, cp, cose, mmr, list);

  const direct = Array.isArray(stated.witnesses) ? stated.witnesses : [];
  if (!direct.length) return out;
  out.receipts = await checkReceipts(cp, direct, list);
  out.status = overall(out.receipts);
  if (out.status === "pass") out.rung = "witnessed";
  return out;
}

async function checkCadence(out, chain, cp, cose, mmr, list) {
  const failChain = (reason) => {
    out.chain = { status: "fail", reason };
    out.status = "fail";
    return out;
  };
  let leafCp = cp, leafCose = cose;
  if (chain.extent === "part") {
    const earlier = chain.earlier || {};
    let prior;
    try {
      leafCose = b64Decode((earlier.checkpoint || {}).cose, true);
      prior = await verifyCheckpoint(leafCose, mmr);
    } catch (e) {
      return failChain("the earlier checkpoint is malformed");
    }
    if (!prior.ok) return failChain("the earlier checkpoint does not verify: " + prior.reason);
    if (prior.kid !== cp.kid || prior.logId !== cp.logId || prior.size >= cp.size) return failChain("the earlier checkpoint is not an earlier checkpoint of this log, signed by the same key");
    const p = earlier.consistency_proof || {};
    const wire = { v: p.v, kind: p.kind, size_a: asInt(p.old_size), size_b: asInt(p.new_size), old_peaks: p.old_peaks, witness: p.witness, new_peaks: p.new_peaks };
    if (!(await mmr.verifyConsistency(prior.root, prior.size, cp.root, cp.size, wire))) return failChain("the bundle's checkpoint does not extend the earlier one");
    leafCp = prior;
  }
  const size = asInt(chain.size), index = asInt(chain.index);
  if (chain.log_id !== leafCp.logId || size !== leafCp.size) return failChain("the chain does not name this checkpoint");
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** CADENCE_DEPTH || typeof chain.salt !== "string" || !chain.salt || !Array.isArray(chain.path) || chain.path.length !== CADENCE_DEPTH) return failChain("the chain is malformed");
  let node = await cadenceLeaf(chain.log_id, size, bytesToHex(await sha256(leafCose)), chain.salt);
  for (let level = 0; level < CADENCE_DEPTH; level++) {
    const sib = hexToBytes(chain.path[level]);
    if (sib.length !== 32) return failChain("the chain is malformed");
    node = (index >> level) & 1 ? await sha256(concat(Uint8Array.of(1), sib, node)) : await sha256(concat(Uint8Array.of(1), node, sib));
  }
  const inner = chain.cadence || {};
  let cadenceCose, cadence;
  try {
    cadenceCose = b64Decode((inner.checkpoint || {}).cose, true);
    cadence = await verifyCheckpoint(cadenceCose, mmr);
  } catch (e) {
    return failChain("the cadence checkpoint is malformed");
  }
  if (!cadence.ok) return failChain("the cadence checkpoint does not verify: " + cadence.reason);
  if (cadence.kid !== cp.kid) return failChain("the cadence checkpoint is signed by a different key");
  if (inner.log_id !== cadence.logId) return failChain("the cadence log id does not match its checkpoint");
  const proof = inner.inclusion_proof || {};
  if (!(await mmr.verifyInclusion(cadence.root, cadence.size, asInt(inner.entry_index), bytesToHex(node), { ...proof, size: asInt(proof.size), leaf_index: asInt(proof.leaf_index) }))) return failChain("the cadence entry is not included in the cadence checkpoint");
  out.chain = { status: "pass", reason: "the checkpoint is a leaf of a cadence entry included in the cadence checkpoint" };
  out.receipts = await checkReceipts(cadence, inner.witnesses, list);
  out.status = out.receipts.length ? overall(out.receipts) : "withheld";
  if (out.status === "pass") {
    out.rung = chain.extent === "part" ? "witnessed_in_part" : "witnessed";
    if (chain.extent === "part") {
      out.stepsWitnessed = mmr.leafCountFromSize(leafCp.size);
      out.steps = mmr.leafCountFromSize(cp.size);
    }
  }
  return out;
}
