import fs from "fs";
const py = fs.readFileSync("/tmp/scitt/hosted_profiles/hosted.py","utf8");
// pull the CAPSULE_JS blob that contains evaluateRitual + checkWitness
const start = py.indexOf("function evaluateRitual(");
const helpersStart = py.lastIndexOf("function findChainGaps(", start);
const end = py.indexOf("async function renderRitual(", start);
let js = py.slice(helpersStart, end);
// minimal stubs for helpers referenced but defined elsewhere
const stub = `
function isH64(s){return typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);}
function unwrapEnvelope(c){return (c&&c.capsule&&typeof c.capsule==="object")?c.capsule:c;}
function sh(x){return String(x||"").slice(0,8);}
function parseAac(){return{privlog:[]};}
function _capMismatched(){return false;}
`;
const mod = await import("data:text/javascript," + encodeURIComponent(stub + js + "\nexport {evaluateRitual, checkWitness, describeBundle};"));
const {evaluateRitual, checkWitness, describeBundle} = mod;
const id = n => String(n).repeat(64).slice(0,64);
const cap = (i,parent) => { const c={capsule_id:id(i)}; if(parent) c.chain={parent_capsule_id:id(parent)}; return c; };
const stage = (r,name) => r.stages.find(s=>s.name===name);

// --- the goose bundle: 2 records, NEITHER declares a chain ---
let r = evaluateRitual([cap(1),cap(2)], {held:1,configured:1,reachable:true}, null);
const seq = stage(r,"Sequence");
console.log("goose-shaped  Sequence:", seq.status, "|", seq.detail);
if (seq.status === "pass") { console.error("FAIL: unchained bundle still passes Sequence"); process.exit(1); }
const wit = stage(r,"Witness");
console.log("goose-shaped  Witness :", wit.status, "|", wit.detail);
if (wit.status === "pass") { console.error("FAIL: 1-of-2 coverage still passes Witness"); process.exit(1); }

// --- the inference bundle: 4 records, properly chained ---
r = evaluateRitual([cap(1),cap(2,1),cap(3,2),cap(4,3)], {held:4,configured:4,reachable:true}, null);
const seq2 = stage(r,"Sequence");
console.log("chained x4    Sequence:", seq2.status, "|", seq2.detail);
if (seq2.status !== "pass") { console.error("FAIL: genuine chain no longer passes"); process.exit(1); }
console.log("chained x4    Witness :", stage(r,"Witness").status);

// --- a real gap must still fail ---
r = evaluateRitual([cap(1),cap(3,9)], {reachable:false}, null);
const seq3 = stage(r,"Sequence");
console.log("missing parent Sequence:", seq3.status, "|", seq3.detail);
if (seq3.status !== "fail") { console.error("FAIL: real gap no longer detected"); process.exit(1); }

// --- partial: 3 records, only one link declared ---
r = evaluateRitual([cap(1),cap(2,1),cap(3)], {reachable:false}, null);
const seq4 = stage(r,"Sequence");
console.log("partial chain Sequence:", seq4.status, "|", seq4.detail);
if (seq4.status === "pass") { console.error("FAIL: partial chain passes"); process.exit(1); }


// --- plain-language summary must render on a CLEAN bundle ---
const real = [
 {capsule_id:id(1),action_type:"fyi",operator:"capsule-emit-mesh-poc-demo",timestamp:"2026-08-11 06:07:09",
  disposition:{decision:"accept",approver:"policy",human_disposed:false},
  assurance:{attestation_mode:"self_attested",effect_mode:"dispatched_unconfirmed",ledger_mode:"standalone"},
  model_attestation:{compute_attestation:{agent_input_digest:id(7),agent_output_digest:id(8)}}},
 {capsule_id:id(2),action_type:"decide",operator:"capsule-emit-mesh-poc-demo",timestamp:"2026-08-11 06:07:11",
  disposition:{decision:"accept",approver:"policy",human_disposed:false},
  assurance:{attestation_mode:"self_attested",effect_mode:"dispatched_unconfirmed",ledger_mode:"standalone"},
  model_attestation:{compute_attestation:{agent_input_digest:id(7),agent_output_digest:id(8)}}}];
const r5 = evaluateRitual(real, {held:1,configured:1,reachable:true}, null);
if (!r5.summary) { console.error("FAIL: no summary on clean bundle"); process.exit(1); }
console.log("\n--- summary on the real goose bundle ---\n" + r5.summary.text + "\n");
for (const must of ["2 records","No human approved","self-attested","dispatched but unconfirmed","digests only"]) {
  if (!r5.summary.text.includes(must)) { console.error("FAIL: summary missing:", must); process.exit(1); }
}
if (describeBundle([]) !== null) { console.error("FAIL: empty bundle should return null"); process.exit(1); }
const r6 = evaluateRitual([{capsule_id:id(1),action_type:"decide",disposition:{decision:"reject",human_disposed:true}}], null, null);
if (!r6.summary.text.includes("refused")) { console.error("FAIL: refusal not described"); process.exit(1); }
console.log("refusal case:", r6.summary.text);

console.log("\nALL RITUAL CHECKS PASSED");
