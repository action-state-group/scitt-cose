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
const mod = await import("data:text/javascript," + encodeURIComponent(stub + js + "\nexport {evaluateRitual, checkWitness};"));
const {evaluateRitual, checkWitness} = mod;
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

console.log("\nALL RITUAL CHECKS PASSED");
