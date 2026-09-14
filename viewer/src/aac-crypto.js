// Deliberately import the browser-safe modules from the pinned package rather
// than its aggregate entrypoint, which also exports producer-envelope CBOR.
import { computeCapsuleId, verifyClass1 } from "../node_modules/@action-state-group/agent-action-capsule/dist/verify.js";
import { decodeFragment, encodeFragment, verifyBundle } from "../node_modules/@action-state-group/agent-action-capsule/dist/bundle.js";
import { verifyDisclosureEnvelope } from "../node_modules/@action-state-group/agent-action-capsule/dist/disclosure-envelope.js";
import { jcs, jsonDigest } from "../node_modules/@action-state-group/agent-action-capsule/dist/json.js";

const text = new TextDecoder("utf-8", { fatal: true });

/** The browser-facing boundary for the hosted viewer.  Presentation code uses
 * this object; all AAC canonicalization and verification stays upstream. */
globalThis.AacCrypto = Object.freeze({
  computeCapsuleId,
  verifyClass1,
  verifyDisclosureEnvelope,
  verifyBundle,
  encodeFragment,
  decodeFragment,
  jsonDigest,
  canonicalPayloadText(value) {
    return text.decode(jcs(value));
  },
});
