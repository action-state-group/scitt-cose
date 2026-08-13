import fs from "fs";
const py = fs.readFileSync("/tmp/scitt/hosted_profiles/hosted.py","utf8");
const bStart = py.indexOf('BUNDLE_JS = r"""');
const dStart = py.indexOf("function describeBundle(capsules){", bStart);
const dEnd = py.indexOf("\n}", py.indexOf('it makes no claim the ritual did not check"};', dStart)) + 2;
const stub = `
function isH64(s){return typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);}
function unwrapEnvelope(c){return (c&&c.capsule&&typeof c.capsule==="object")?c.capsule:c;}
`;
const mod = await import("data:text/javascript," + encodeURIComponent(stub + py.slice(dStart,dEnd) + "\nexport {describeBundle};"));
const id = n => String(n).repeat(64).slice(0,64);
const r = mod.describeBundle([
 {capsule_id:id(1),action_type:"decide",operator:"op",timestamp:"2026-08-11 06:07:08",
  disposition:{decision:"accept",human_disposed:false},
  assurance:{attestation_mode:"self_attested",effect_mode:"confirmed"},
  model_attestation:{compute_attestation:{agent_input_digest:id(7)}}}]);
if(!r||!r.text.includes("1 record")){console.error("FAIL",r);process.exit(1);}
console.log("BUNDLE_JS describeBundle works:\n  " + r.text);
if(mod.describeBundle([])!==null){console.error("FAIL: empty");process.exit(1);}
console.log("\nBUNDLE SURFACE OK");
