// The browser-facing boundary for the bundle page's witness checks (see
// witness.js). Built separately from aac-crypto.js: it needs only cborg.
import { checkWitnessEvidence, parseWitnessList } from "./witness.js";

globalThis.WitnessCheck = Object.freeze({ checkWitnessEvidence, parseWitnessList });
