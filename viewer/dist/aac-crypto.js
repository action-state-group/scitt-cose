(() => {
  // node_modules/@action-state-group/agent-action-capsule/dist/json.js
  var utf8 = new TextDecoder("utf-8", { fatal: true });
  var encoder = new TextEncoder;
  var MAX_DEPTH = 1000;
  class JsonNumber {
    raw;
    constructor(raw) {
      this.raw = raw;
    }
  }

  class JcsFloatError extends TypeError {
    path;
    constructor(path) {
      super(`float at ${path}`);
      this.path = path;
      this.name = "TypeError";
    }
  }

  class JcsUnsafeIntegerError extends TypeError {
    path;
    constructor(path) {
      super(`unsafe integer at ${path}`);
      this.path = path;
      this.name = "TypeError";
    }
  }
  function asJsonObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof JsonNumber) ? value : undefined;
  }
  function isHex64(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
  }
  function assertString(value) {
    for (let i = 0;i < value.length; i += 1) {
      const unit = value.charCodeAt(i);
      if (unit >= 55296 && unit <= 56319) {
        const next = value.charCodeAt(++i);
        if (!(next >= 56320 && next <= 57343))
          throw new TypeError("unpaired high surrogate");
      } else if (unit >= 56320 && unit <= 57343)
        throw new TypeError("unpaired low surrogate");
    }
  }
  function renderString(value) {
    assertString(value);
    return JSON.stringify(value);
  }
  function render(value, path, seen, depth) {
    if (depth > MAX_DEPTH)
      throw new TypeError(`JSON nesting exceeds ${MAX_DEPTH}`);
    if (value === null)
      return "null";
    if (typeof value === "boolean")
      return value ? "true" : "false";
    if (typeof value === "string")
      return renderString(value);
    if (value instanceof JsonNumber) {
      if (/[.eE]/u.test(value.raw))
        throw new JcsFloatError(path);
      const integer = BigInt(value.raw);
      if (integer > BigInt(Number.MAX_SAFE_INTEGER) || integer < BigInt(Number.MIN_SAFE_INTEGER))
        throw new JcsUnsafeIntegerError(path);
      return integer === 0n ? "0" : value.raw;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value))
        throw new JcsFloatError(path);
      if (!Number.isSafeInteger(value))
        throw new JcsUnsafeIntegerError(path);
      return Object.is(value, -0) ? "0" : String(value);
    }
    if (typeof value !== "object" || value === undefined)
      throw new TypeError(`unsupported JSON value at ${path}`);
    if (seen.has(value))
      throw new TypeError(`cyclic JSON value at ${path}`);
    seen.add(value);
    try {
      if (Array.isArray(value)) {
        for (let i = 0;i < value.length; i += 1)
          if (!(i in value))
            throw new TypeError(`sparse array at ${path}[${i}]`);
        return `[${value.map((item, i) => render(item, `${path}[${i}]`, seen, depth + 1)).join(",")}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null)
        throw new TypeError(`non-plain object at ${path}`);
      const record = value;
      const keys = Object.keys(record).sort();
      return `{${keys.map((key) => `${renderString(key)}:${render(record[key], `${path}.${key}`, seen, depth + 1)}`).join(",")}}`;
    } finally {
      seen.delete(value);
    }
  }
  function jcs(value) {
    return encoder.encode(render(value, "$", new Set, 0));
  }
  async function sha256Hex(value) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", value);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  async function jsonDigest(value) {
    return sha256Hex(jcs(value));
  }

  // node_modules/@action-state-group/agent-action-capsule/dist/references.js
  function referenceFindings(capsule, purposes) {
    if (capsule.format_version !== "4")
      return [];
    if (!("references" in capsule))
      return [];
    const findings = [];
    const add = (code, detail, check, severity = "error") => {
      findings.push({ code, detail, check, severity });
    };
    if (!Array.isArray(capsule.references)) {
      add("references_malformed", "references MUST be an array (§5.5.5)", 1);
      return findings;
    }
    const parent = asJsonObject(capsule.chain)?.parent_capsule_id;
    for (const [i, raw] of capsule.references.entries()) {
      const path = `references[${i}]`;
      const ref = asJsonObject(raw);
      if (ref === undefined) {
        add("reference_malformed", `${path} MUST be an object (§5.5.5)`, 1);
        continue;
      }
      for (const field of ["type", "digest_alg", "digest"]) {
        if (typeof ref[field] !== "string" || ref[field] === "") {
          add("reference_malformed", `${path}.${field} MUST be a non-empty string (§5.5.5)`, 1);
        }
      }
      if (ref.type === "agent-action-capsule" && ref.digest_alg === "SHA-256") {
        if (typeof ref.digest === "string" && ref.digest !== "" && !isHex64(ref.digest)) {
          add("reference_malformed", `${path}.digest MUST be an AAC Capsule ID for agent-action-capsule/SHA-256 (§5.5.5)`, 1);
        }
        if (typeof parent === "string" && parent !== "" && ref.digest === parent) {
          add("reference_duplicates_chain_parent", `${path} duplicates chain.parent_capsule_id (§5.5.5)`, 6);
        }
      }
      if ("citation_purpose" in ref) {
        if (typeof ref.citation_purpose !== "string" || ref.citation_purpose === "") {
          add("reference_malformed", `${path}.citation_purpose MUST be a non-empty string (§5.5.5)`, 1);
        } else if (!purposes.has(ref.citation_purpose)) {
          add("unknown_registry_value", `${path}.citation_purpose is not seeded; informational, not rejected (§12)`, 8, "info");
        }
      }
      if ("log_coordinates" in ref) {
        const coordinates = asJsonObject(ref.log_coordinates);
        if (coordinates === undefined) {
          add("reference_log_coordinates_malformed", `${path}.log_coordinates MUST be an object (§5.5.5)`, 1);
          continue;
        }
        for (const field of ["log_id", "leaf_index", "inclusion_proof"]) {
          if (!(field in coordinates) || coordinates[field] === null) {
            add("reference_log_coordinates_malformed", `${path}.log_coordinates requires ${field} (§5.5.5)`, 1);
          }
        }
      }
    }
    return findings;
  }
  // node_modules/@action-state-group/agent-action-capsule/dist/data/cpb_provisional.json
  var cpb_provisional_default = {
    schema_version: "1",
    _vendored_from: "action-state-group/scitt-payload-binding",
    _vendored_source: "spec/cpb-provisional-registry.md",
    _vendored_commit: "e0ad1c7e0b0248b9aed25c747f174548cb8e141d",
    _vendored_note: "Machine-readable resolver projection of the CPB *provisional* (Rung 3) Artifact Type entries. Lossy by design: name -> status + governed closed-set values. The markdown is normative; do not hand-edit -- re-run scripts/vendor_cpb_registry.py.",
    provisional_artifact_types: {
      "verifiable-agent-conversation": {
        status: "provisional",
        reference: "",
        governed_values: {}
      },
      "trace-trust-record": {
        status: "provisional",
        reference: "`agentrust-io/trace-spec` @ `e0afe8eba628244afd591433014b182530a0c11c`",
        governed_values: {}
      },
      "mesh-inference-exchange": {
        status: "provisional",
        reference: "`action-state-group/capsule-emit-mesh` @ `0304296` (`mesh_record_emitter.py`, `mesh_record_verifier.py`)",
        governed_values: {
          terminal_state: [
            "completed",
            "policy_denied",
            "request_invalid",
            "backend_error",
            "transport_error",
            "client_cancelled",
            "timed_out",
            "evidence_unavailable"
          ],
          observation_point: [
            "gateway_ingress",
            "serving_host_ingress",
            "backend_dispatch",
            "client_egress"
          ]
        },
        capsule_field_values: {
          "effect.type": ["inference_completion"],
          effect_attestation: ["host_served_observed"],
          "chain.relation": ["follows"]
        },
        capsule_field_values_source: "action-state-group/capsule-emit-mesh plugins/admission-policy/src/capsule_emit.rs (effect_type, effect_attestation, chain.relation) and capsule_sidecar.py"
      },
      "mmr-checkpoint": {
        status: "provisional",
        reference: "`action-state-group/capsule-ledger` @ `0fef1b2` (`capsule_ledger/mmr/checkpoint.py`, `capsule_ledger/mmr/core.py`)",
        governed_values: {}
      }
    },
    snapshot_sha256: "c401fceb810116b64e3ea2f824d03bd016a63c7e47daf7a74ab239adf35e7cbc"
  };

  // node_modules/@action-state-group/agent-action-capsule/dist/provisional.js
  function provisionalClass(registry, value) {
    const classes = cpb_provisional_default.provisional_artifact_types;
    for (const [name, entry] of Object.entries(classes)) {
      if (entry.capsule_field_values?.[registry]?.includes(value))
        return name;
    }
    return;
  }

  // node_modules/@action-state-group/agent-action-capsule/dist/registries.js
  var registries = Object.freeze({
    verdict_class: new Set([
      "executed",
      "blocked",
      "hitl_dispatched",
      "denied",
      "timeout",
      "errored",
      "engine_failure",
      "deferred",
      "needs_decision",
      "expired",
      "escalated",
      "resolved",
      "epoch_boundary"
    ]),
    "disposition.decision": new Set([
      "accept",
      "reject",
      "needs_input",
      "deferred"
    ]),
    "effect.type": new Set(["write_order", "send_payment"]),
    irreversibility_class: new Set([
      "two_way",
      "one_way_recoverable",
      "one_way_consequential",
      "one_way_terminal"
    ]),
    effect_attestation: new Set(["gate_executed", "runtime_claimed"]),
    "chain.relation": new Set(["confirms", "supersedes", "epoch_opens"]),
    citation_purpose: new Set(["acted_on", "responds_to"])
  });
  var disclosureEligibleFields = Object.freeze({
    agent_input: "model_attestation.compute_attestation.agent_input_digest",
    agent_output: "model_attestation.compute_attestation.agent_output_digest"
  });

  // node_modules/@action-state-group/agent-action-capsule/dist/verify.js
  var object = asJsonObject;
  async function computeCapsuleId(capsule) {
    if (capsule.format_version !== "4")
      throw new TypeError('format_version must be "4"');
    if (!("canonicalization_id" in capsule))
      throw new TypeError("canonicalization_id is required");
    const copy = {};
    const declared = capsule.canonicalization_id;
    if (declared !== undefined && typeof declared !== "string")
      throw new TypeError("canonicalization_id must be a string");
    if (declared !== undefined && declared !== "jcs")
      throw new TypeError(`unsupported canonicalization_id ${JSON.stringify(declared)}`);
    for (const [key, value] of Object.entries(capsule)) {
      if (key === "capsule_id" || key === "signature" || key === "key_id")
        continue;
      copy[key] = value;
    }
    return sha256Hex(jcs(copy));
  }
  function pathFind(value, predicate, path = "") {
    if (value instanceof JsonNumber)
      return predicate(value) ? [path || "<root>"] : [];
    if (Array.isArray(value))
      return value.flatMap((child, index) => pathFind(child, predicate, `${path}[${index}]`));
    const record = object(value);
    if (record === undefined)
      return [];
    return Object.keys(record).sort().flatMap((key) => pathFind(record[key], predicate, path === "" ? key : `${path}.${key}`));
  }
  var v4IrreversibilityClasses = registries.irreversibility_class;
  async function verifyClass1(capsule, store, extensions = {}) {
    const findings = [];
    const add = (code, detail, check, severity = "error") => {
      findings.push(check === undefined ? { code, detail, severity } : { code, detail, severity, check });
    };
    const top = object(capsule);
    if (top === undefined)
      return {
        ok: false,
        findings: [
          {
            code: "not_an_object",
            detail: "Capsule is not a JSON object",
            severity: "error",
            check: 1
          }
        ],
        assurance: {}
      };
    const references = referenceFindings(top, new Set([
      ...registries.citation_purpose,
      ...extensions.citation_purpose ?? []
    ]));
    for (const field of [
      "spec_version",
      "format_version",
      "capsule_id",
      "action_id",
      "action_type",
      "operator",
      "developer",
      "timestamp"
    ]) {
      if (!(field in top))
        add("missing_required_field", `${field} is REQUIRED (§5.1)`, 1);
      else if (typeof top[field] !== "string")
        add("field_not_string", `${field} MUST be a string (§5.1)`, 1);
    }
    const carriedId = typeof top.capsule_id === "string" && isHex64(top.capsule_id) ? top.capsule_id : undefined;
    if (typeof top.capsule_id === "string" && carriedId === undefined)
      add("capsule_id_malformed", "capsule_id MUST be 64 lowercase hex (§5.1)", 1);
    if (typeof top.action_type === "string" && top.action_type !== "fyi" && top.action_type !== "decide")
      add("action_type_invalid", "action_type MUST be 'fyi' or 'decide' (§5.1)", 1);
    if (typeof top.format_version === "string") {
      if (top.format_version === "4" && top.canonicalization_id !== "jcs")
        add(!("canonicalization_id" in top) ? "canonicalization_id_missing" : typeof top.canonicalization_id === "string" ? "canonicalization_profile_mismatch" : "canonicalization_id_not_string", 'format_version "4" REQUIRES canonicalization_id="jcs" (§5.1)', 1);
      else if (top.format_version !== "4")
        add("unsupported_format_version", `format_version ${JSON.stringify(top.format_version)} is not supported; expected "4" (§5.1)`, 1);
    }
    for (const field of [
      "effect",
      "assurance",
      "disposition",
      "chain",
      "cross_party"
    ])
      if (field in top && object(top[field]) === undefined)
        add("block_not_object", `${field} MUST be a JSON object when present`, 1);
    if ("constraints" in top && !Array.isArray(top.constraints))
      add("constraints_not_array", "constraints MUST be an array when present (§8.1)", 1);
    for (const path of pathFind(top, (n) => /[.eE]/u.test(n.raw)))
      add("float_in_digest_field", `floating-point value at ${path}; §5.1 forbids it`, 1);
    for (const path of pathFind(top, (n) => !/[.eE]/u.test(n.raw) && (BigInt(n.raw) > 9007199254740991n || BigInt(n.raw) < -9007199254740991n)))
      add("unsafe_integer_in_digest_field", `integer outside the JS-safe range (+/-9007199254740991) at ${path}`, 1);
    const disposition = object(top.disposition);
    if (disposition !== undefined) {
      if (typeof disposition.approver !== "string")
        add("missing_required_field", "disposition.approver is REQUIRED (§5.4)", 1);
      else if (!["human", "policy", "counterparty"].includes(disposition.approver))
        add("approver_invalid", "disposition.approver has an invalid value (§5.4)", 1);
      if (!("decision" in disposition))
        add("missing_required_field", "disposition.decision is REQUIRED (§5.4)", 1);
      if (typeof disposition.human_disposed !== "boolean")
        add("field_not_bool", "disposition.human_disposed MUST be boolean (§5.4)", 1);
      if (disposition.human_disposed === true && disposition.approver !== "human")
        add("dishonest_human_disposed", "human_disposed=true with non-human approver (§5.4)", undefined, "warning");
    }
    findings.push(...references.filter((finding) => finding.check === 1));
    let recomputed;
    const identityProfileValid = top.format_version === "4" && top.canonicalization_id === "jcs";
    if (carriedId !== undefined && identityProfileValid) {
      try {
        recomputed = await computeCapsuleId(top);
        if (recomputed !== carriedId)
          add("capsule_id_mismatch", `recomputed ${recomputed} != carried ${carriedId}`, 2);
      } catch (error) {
        if (!(error instanceof JcsFloatError) && !(error instanceof JcsUnsafeIntegerError))
          add("capsule_id_uncomputable", String(error), 2);
      }
    }
    const effect = object(top.effect);
    const status = typeof effect?.status === "string" ? effect.status : "";
    if (status === "confirmed" && !(typeof effect?.response_digest === "string" && isHex64(effect.response_digest)))
      add("confirmed_without_response", "effect.status 'confirmed' requires 64-hex response_digest (§5.2)", 3);
    const effectMode = effect === undefined || status === "planned" ? "not_applicable" : status === "confirmed" && typeof effect.response_digest === "string" && isHex64(effect.response_digest) ? "confirmed" : "dispatched_unconfirmed";
    const verdict = typeof disposition?.verdict_class === "string" ? disposition.verdict_class : "";
    if (new Set([
      "blocked",
      "hitl_dispatched",
      "denied",
      "engine_failure",
      "deferred",
      "needs_decision",
      "expired",
      "escalated",
      "resolved"
    ]).has(verdict) && effectMode !== "not_applicable")
      add("verdict_effect_conflict", `verdict_class ${JSON.stringify(verdict)} requires effect_mode "not_applicable" (§5.4.2)`, 4);
    if (effectMode === "not_applicable" && effect?.effect_attestation !== undefined && effect.effect_attestation !== null)
      add("effect_attestation_present", "effect_attestation MUST be absent for effect_mode 'not_applicable' (§5.2)", 5);
    if (effect !== undefined && status !== "planned" && (effect.effect_attestation === undefined || effect.effect_attestation === null))
      add("effect_attestation_missing", "dispatched effect requires effect_attestation (§5.2)", 5);
    const chain = object(top.chain);
    if (chain !== undefined) {
      if (!(typeof chain.parent_capsule_id === "string" && isHex64(chain.parent_capsule_id)))
        add("chain_parent_malformed", "chain.parent_capsule_id MUST be 64-hex capsule_id (§5.4.4)", 6);
      if (!("relation" in chain))
        add("missing_required_field", "chain.relation is REQUIRED when chain block is present (§5.4.4)", 6);
      if (store === undefined)
        add("chain_check_store_level", "chain parent-existence and concurrent-supersedes are store-level checks (§6); not run without store", 6, "info");
      else {
        const ids = store instanceof Set ? store : new Set(store.map((item) => typeof item === "string" ? item : object(item)?.capsule_id).filter((id) => typeof id === "string"));
        if (typeof chain.parent_capsule_id === "string" && !ids.has(chain.parent_capsule_id))
          add("chain_parent_missing", `chain parent ${chain.parent_capsule_id} not found in store (§6)`, 6);
      }
    }
    findings.push(...references.filter((finding) => finding.check === 6));
    const crossParty = object(top.cross_party);
    let crossPartyRung;
    if (crossParty !== undefined)
      crossPartyRung = typeof crossParty.counterparty_ref === "string" && isHex64(crossParty.counterparty_ref) && typeof crossParty.correlator === "string" && crossParty.correlator !== "" ? crossParty.substantive === true ? "full_bilateral" : "acknowledged_receipt" : "unilateral_fallback";
    const assurance = {
      effect_mode: effectMode,
      attestation_mode: "self_attested",
      ledger_mode: chain === undefined ? "standalone" : "chained",
      ...crossPartyRung === undefined ? {} : { cross_party_rung: crossPartyRung }
    };
    const stated = object(top.assurance);
    const rank = {
      not_applicable: 0,
      dispatched_unconfirmed: 0,
      confirmed: 1
    };
    if (typeof stated?.effect_mode === "string" && (rank[stated.effect_mode] ?? -1) > rank[effectMode])
      add("assurance_overclaim", `claimed effect_mode ${JSON.stringify(stated.effect_mode)} but verifier derived ${JSON.stringify(effectMode)} (§5.3)`, 7);
    const attestationRank = {
      self_attested: 0,
      anchored: 1
    };
    if (typeof stated?.attestation_mode === "string" && (attestationRank[stated.attestation_mode] ?? -1) > attestationRank.self_attested)
      add("assurance_overclaim", `claimed attestation_mode ${JSON.stringify(stated.attestation_mode)} but verifier derived "self_attested" (§5.3)`, 7, "info");
    const ledgerRank = {
      standalone: 0,
      chained: 1,
      anchored: 2
    };
    const ledgerMode = chain === undefined ? "standalone" : "chained";
    if (typeof stated?.ledger_mode === "string" && (ledgerRank[stated.ledger_mode] ?? -1) > ledgerRank[ledgerMode])
      add("assurance_overclaim", `claimed ledger_mode ${JSON.stringify(stated.ledger_mode)} but verifier derived ${JSON.stringify(ledgerMode)} (§5.3)`, 7, "info");
    const crossRank = {
      unilateral_fallback: 0,
      acknowledged_receipt: 1,
      full_bilateral: 2
    };
    if (typeof stated?.cross_party_rung === "string" && (crossRank[stated.cross_party_rung] ?? -1) > crossRank[crossPartyRung ?? "unilateral_fallback"])
      add("assurance_overclaim", `claimed cross_party_rung ${JSON.stringify(stated.cross_party_rung)} but verifier derived ${JSON.stringify(crossPartyRung ?? "unilateral_fallback")} (§5.3 Cross-party assurance)`, 7, "info");
    const fields = [
      ["verdict_class", disposition, "verdict_class"],
      ["disposition.decision", disposition, "decision"],
      ["effect.type", effect, "type"],
      ["irreversibility_class", effect, "irreversibility_class"],
      ["effect_attestation", effect, "effect_attestation"],
      ["chain.relation", chain, "relation"]
    ];
    for (const [registry, block, member] of fields) {
      const value = block?.[member];
      const accepted = new Set([
        ...registries[registry] ?? [],
        ...extensions[registry] ?? []
      ]);
      if (typeof value === "string" && !accepted.has(value)) {
        const provisional = provisionalClass(registry, value);
        if (provisional !== undefined) {
          add("known_provisional_registry_value", `${member}=${JSON.stringify(value)} resolves known status 'provisional' via vendored CPB registry (payload class ${JSON.stringify(provisional)}); informational, not rejected (§12)`, 8, "info");
          continue;
        }
        add("unknown_registry_value", `${member}=${JSON.stringify(value)} is not a seeded ${registry} value; informational, not rejected (§12)`, 8, "info");
        if (registry === "effect_attestation")
          add("effect_attestation_graded_floor", "unknown effect_attestation is graded no stronger than 'runtime_claimed' (§5.2)", 8, "info");
      }
    }
    findings.push(...references.filter((finding) => finding.check === 8));
    return {
      ok: !findings.some((finding) => finding.severity === "error"),
      findings,
      assurance,
      ...recomputed === undefined ? {} : { capsuleId: recomputed }
    };
  }

  // node_modules/cborg/lib/is.js
  var objectTypeNames = [
    "Object",
    "RegExp",
    "Date",
    "Error",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "ArrayBuffer",
    "SharedArrayBuffer",
    "DataView",
    "Promise",
    "URL",
    "HTMLElement",
    "Int8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
    "Tagged"
  ];
  function is(value) {
    if (value === null) {
      return "null";
    }
    if (value === undefined) {
      return "undefined";
    }
    if (value === true || value === false) {
      return "boolean";
    }
    const typeOf = typeof value;
    if (typeOf === "string" || typeOf === "number" || typeOf === "bigint" || typeOf === "symbol") {
      return typeOf;
    }
    if (typeOf === "function") {
      return "Function";
    }
    if (Array.isArray(value)) {
      return "Array";
    }
    if (value instanceof Uint8Array) {
      return "Uint8Array";
    }
    if (value.constructor === Object) {
      return "Object";
    }
    const objectType = getObjectType(value);
    if (objectType) {
      return objectType;
    }
    return "Object";
  }
  function getObjectType(value) {
    const objectTypeName = Object.prototype.toString.call(value).slice(8, -1);
    if (objectTypeNames.includes(objectTypeName)) {
      return objectTypeName;
    }
    return;
  }

  // node_modules/cborg/lib/token.js
  class Type {
    constructor(major, name, terminal) {
      this.major = major;
      this.majorEncoded = major << 5;
      this.name = name;
      this.terminal = terminal;
    }
    toString() {
      return `Type[${this.major}].${this.name}`;
    }
    compare(typ) {
      return this.major < typ.major ? -1 : this.major > typ.major ? 1 : 0;
    }
    static equals(a, b) {
      return a === b || a.major === b.major && a.name === b.name;
    }
  }
  Type.uint = new Type(0, "uint", true);
  Type.negint = new Type(1, "negint", true);
  Type.bytes = new Type(2, "bytes", true);
  Type.string = new Type(3, "string", true);
  Type.array = new Type(4, "array", false);
  Type.map = new Type(5, "map", false);
  Type.tag = new Type(6, "tag", false);
  Type.float = new Type(7, "float", true);
  Type.false = new Type(7, "false", true);
  Type.true = new Type(7, "true", true);
  Type.null = new Type(7, "null", true);
  Type.undefined = new Type(7, "undefined", true);
  Type.break = new Type(7, "break", true);

  class Token {
    constructor(type, value, encodedLength) {
      this.type = type;
      this.value = value;
      this.encodedLength = encodedLength;
      this.encodedBytes = undefined;
      this.byteValue = undefined;
    }
    toString() {
      return `Token[${this.type}].${this.value}`;
    }
  }

  // node_modules/cborg/lib/byte-utils.js
  var useBuffer = globalThis.process && !globalThis.process.browser && globalThis.Buffer && typeof globalThis.Buffer.isBuffer === "function";
  var textEncoder = new TextEncoder;
  function isBuffer(buf) {
    return useBuffer && globalThis.Buffer.isBuffer(buf);
  }
  function asU8A(buf) {
    if (!(buf instanceof Uint8Array)) {
      return Uint8Array.from(buf);
    }
    return isBuffer(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : buf;
  }
  var FROM_STRING_THRESHOLD_BUFFER = 24;
  var FROM_STRING_THRESHOLD_TEXTENCODER = 200;
  var fromString = useBuffer ? (string) => {
    return string.length >= FROM_STRING_THRESHOLD_BUFFER ? globalThis.Buffer.from(string) : utf8ToBytes(string);
  } : (string) => {
    return string.length >= FROM_STRING_THRESHOLD_TEXTENCODER ? textEncoder.encode(string) : utf8ToBytes(string);
  };
  var fromArray = (arr) => {
    return Uint8Array.from(arr);
  };
  var slice = useBuffer ? (bytes, start, end) => {
    if (isBuffer(bytes)) {
      return new Uint8Array(bytes.subarray(start, end));
    }
    return bytes.slice(start, end);
  } : (bytes, start, end) => {
    return bytes.slice(start, end);
  };
  var concat = useBuffer ? (chunks, length) => {
    chunks = chunks.map((c) => c instanceof Uint8Array ? c : globalThis.Buffer.from(c));
    return asU8A(globalThis.Buffer.concat(chunks, length));
  } : (chunks, length) => {
    const out = new Uint8Array(length);
    let off = 0;
    for (let b of chunks) {
      if (off + b.length > out.length) {
        b = b.subarray(0, out.length - off);
      }
      out.set(b, off);
      off += b.length;
    }
    return out;
  };
  var alloc = useBuffer ? (size) => {
    return globalThis.Buffer.allocUnsafe(size);
  } : (size) => {
    return new Uint8Array(size);
  };
  function compare(b1, b2) {
    if (isBuffer(b1) && isBuffer(b2)) {
      return b1.compare(b2);
    }
    for (let i = 0;i < b1.length; i++) {
      if (b1[i] === b2[i]) {
        continue;
      }
      return b1[i] < b2[i] ? -1 : 1;
    }
    return 0;
  }
  function utf8ToBytes(str) {
    const out = [];
    let p = 0;
    for (let i = 0;i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 128) {
        out[p++] = c;
      } else if (c < 2048) {
        out[p++] = c >> 6 | 192;
        out[p++] = c & 63 | 128;
      } else if ((c & 64512) === 55296 && i + 1 < str.length && (str.charCodeAt(i + 1) & 64512) === 56320) {
        c = 65536 + ((c & 1023) << 10) + (str.charCodeAt(++i) & 1023);
        out[p++] = c >> 18 | 240;
        out[p++] = c >> 12 & 63 | 128;
        out[p++] = c >> 6 & 63 | 128;
        out[p++] = c & 63 | 128;
      } else {
        if (c >= 55296 && c <= 57343) {
          c = 65533;
        }
        out[p++] = c >> 12 | 224;
        out[p++] = c >> 6 & 63 | 128;
        out[p++] = c & 63 | 128;
      }
    }
    return out;
  }

  // node_modules/cborg/lib/bl.js
  var defaultChunkSize = 256;

  class Bl {
    constructor(chunkSize = defaultChunkSize) {
      this.chunkSize = chunkSize;
      this.cursor = 0;
      this.maxCursor = -1;
      this.chunks = [];
      this._initReuseChunk = null;
    }
    reset() {
      this.cursor = 0;
      this.maxCursor = -1;
      if (this.chunks.length) {
        this.chunks = [];
      }
      if (this._initReuseChunk !== null) {
        this.chunks.push(this._initReuseChunk);
        this.maxCursor = this._initReuseChunk.length - 1;
      }
    }
    pushByte(byte) {
      let topChunk = this.chunks[this.chunks.length - 1];
      if (this.cursor > this.maxCursor) {
        topChunk = alloc(this.chunkSize);
        this.chunks.push(topChunk);
        this.maxCursor += topChunk.length;
        if (this._initReuseChunk === null) {
          this._initReuseChunk = topChunk;
        }
      }
      const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
      topChunk[chunkPos] = byte;
      this.cursor++;
    }
    push(bytes) {
      let topChunk = this.chunks[this.chunks.length - 1];
      const newMax = this.cursor + bytes.length;
      if (newMax <= this.maxCursor + 1) {
        const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
        topChunk.set(bytes, chunkPos);
      } else {
        if (topChunk) {
          const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
          if (chunkPos < topChunk.length) {
            this.chunks[this.chunks.length - 1] = topChunk.subarray(0, chunkPos);
            this.maxCursor = this.cursor - 1;
          }
        }
        if (bytes.length < 64 && bytes.length < this.chunkSize) {
          topChunk = alloc(this.chunkSize);
          this.chunks.push(topChunk);
          this.maxCursor += topChunk.length;
          if (this._initReuseChunk === null) {
            this._initReuseChunk = topChunk;
          }
          topChunk.set(bytes, 0);
        } else {
          this.chunks.push(bytes);
          this.maxCursor += bytes.length;
        }
      }
      this.cursor += bytes.length;
    }
    toBytes(reset = false) {
      let byts;
      if (this.chunks.length === 1) {
        const chunk = this.chunks[0];
        if (reset && this.cursor > chunk.length / 2) {
          byts = this.cursor === chunk.length ? chunk : chunk.subarray(0, this.cursor);
          this._initReuseChunk = null;
          this.chunks = [];
        } else {
          byts = slice(chunk, 0, this.cursor);
        }
      } else {
        byts = concat(this.chunks, this.cursor);
      }
      if (reset) {
        this.reset();
      }
      return byts;
    }
  }

  class U8Bl {
    constructor(dest) {
      this.dest = dest;
      this.cursor = 0;
      this.chunks = [dest];
    }
    reset() {
      this.cursor = 0;
    }
    pushByte(byte) {
      if (this.cursor >= this.dest.length) {
        throw new Error("write out of bounds, destination buffer is too small");
      }
      this.dest[this.cursor++] = byte;
    }
    push(bytes) {
      if (this.cursor + bytes.length > this.dest.length) {
        throw new Error("write out of bounds, destination buffer is too small");
      }
      this.dest.set(bytes, this.cursor);
      this.cursor += bytes.length;
    }
    toBytes(reset = false) {
      const byts = this.dest.subarray(0, this.cursor);
      if (reset) {
        this.reset();
      }
      return byts;
    }
  }

  // node_modules/cborg/lib/common.js
  var decodeErrPrefix = "CBOR decode error:";
  var encodeErrPrefix = "CBOR encode error:";
  var uintMinorPrefixBytes = [];
  uintMinorPrefixBytes[23] = 1;
  uintMinorPrefixBytes[24] = 2;
  uintMinorPrefixBytes[25] = 3;
  uintMinorPrefixBytes[26] = 5;
  uintMinorPrefixBytes[27] = 9;
  function assertEnoughData(data, pos, need) {
    if (data.length - pos < need) {
      throw new Error(`${decodeErrPrefix} not enough data for type`);
    }
  }

  // node_modules/cborg/lib/0uint.js
  var uintBoundaries = [24, 256, 65536, 4294967296, BigInt("18446744073709551616")];
  function readUint8(data, offset, options) {
    assertEnoughData(data, offset, 1);
    const value = data[offset];
    if (options.strict === true && value < uintBoundaries[0]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint16(data, offset, options) {
    assertEnoughData(data, offset, 2);
    const value = data[offset] << 8 | data[offset + 1];
    if (options.strict === true && value < uintBoundaries[1]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint32(data, offset, options) {
    assertEnoughData(data, offset, 4);
    const value = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
    if (options.strict === true && value < uintBoundaries[2]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint64(data, offset, options) {
    assertEnoughData(data, offset, 8);
    const hi = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
    const lo = data[offset + 4] * 16777216 + (data[offset + 5] << 16) + (data[offset + 6] << 8) + data[offset + 7];
    const value = (BigInt(hi) << BigInt(32)) + BigInt(lo);
    if (options.strict === true && value < uintBoundaries[3]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    if (value <= Number.MAX_SAFE_INTEGER) {
      return Number(value);
    }
    if (options.allowBigInt === true) {
      return value;
    }
    throw new Error(`${decodeErrPrefix} integers outside of the safe integer range are not supported`);
  }
  function decodeUint8(data, pos, _minor, options) {
    return new Token(Type.uint, readUint8(data, pos + 1, options), 2);
  }
  function decodeUint16(data, pos, _minor, options) {
    return new Token(Type.uint, readUint16(data, pos + 1, options), 3);
  }
  function decodeUint32(data, pos, _minor, options) {
    return new Token(Type.uint, readUint32(data, pos + 1, options), 5);
  }
  function decodeUint64(data, pos, _minor, options) {
    return new Token(Type.uint, readUint64(data, pos + 1, options), 9);
  }
  function encodeUint(writer, token) {
    return encodeUintValue(writer, 0, token.value);
  }
  function encodeUintValue(writer, major, uint) {
    if (uint < uintBoundaries[0]) {
      const nuint = Number(uint);
      writer.pushByte(major | nuint);
    } else if (uint < uintBoundaries[1]) {
      const nuint = Number(uint);
      writer.push([major | 24, nuint]);
    } else if (uint < uintBoundaries[2]) {
      const nuint = Number(uint);
      writer.push([major | 25, nuint >>> 8, nuint & 255]);
    } else if (uint < uintBoundaries[3]) {
      const nuint = Number(uint);
      writer.push([major | 26, nuint >>> 24 & 255, nuint >>> 16 & 255, nuint >>> 8 & 255, nuint & 255]);
    } else {
      const buint = BigInt(uint);
      if (buint < uintBoundaries[4]) {
        const set = [major | 27, 0, 0, 0, 0, 0, 0, 0];
        let lo = Number(buint & BigInt(4294967295));
        let hi = Number(buint >> BigInt(32) & BigInt(4294967295));
        set[8] = lo & 255;
        lo = lo >> 8;
        set[7] = lo & 255;
        lo = lo >> 8;
        set[6] = lo & 255;
        lo = lo >> 8;
        set[5] = lo & 255;
        set[4] = hi & 255;
        hi = hi >> 8;
        set[3] = hi & 255;
        hi = hi >> 8;
        set[2] = hi & 255;
        hi = hi >> 8;
        set[1] = hi & 255;
        writer.push(set);
      } else {
        throw new Error(`${decodeErrPrefix} encountered BigInt larger than allowable range`);
      }
    }
  }
  encodeUint.encodedSize = function encodedSize(token) {
    return encodeUintValue.encodedSize(token.value);
  };
  encodeUintValue.encodedSize = function encodedSize2(uint) {
    if (uint < uintBoundaries[0]) {
      return 1;
    }
    if (uint < uintBoundaries[1]) {
      return 2;
    }
    if (uint < uintBoundaries[2]) {
      return 3;
    }
    if (uint < uintBoundaries[3]) {
      return 5;
    }
    return 9;
  };
  encodeUint.compareTokens = function compareTokens(tok1, tok2) {
    return tok1.value < tok2.value ? -1 : tok1.value > tok2.value ? 1 : 0;
  };

  // node_modules/cborg/lib/1negint.js
  function decodeNegint8(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint8(data, pos + 1, options), 2);
  }
  function decodeNegint16(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint16(data, pos + 1, options), 3);
  }
  function decodeNegint32(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint32(data, pos + 1, options), 5);
  }
  var neg1b = BigInt(-1);
  var pos1b = BigInt(1);
  function decodeNegint64(data, pos, _minor, options) {
    const int = readUint64(data, pos + 1, options);
    if (typeof int !== "bigint") {
      const value = -1 - int;
      if (value >= Number.MIN_SAFE_INTEGER) {
        return new Token(Type.negint, value, 9);
      }
    }
    if (options.allowBigInt !== true) {
      throw new Error(`${decodeErrPrefix} integers outside of the safe integer range are not supported`);
    }
    return new Token(Type.negint, neg1b - BigInt(int), 9);
  }
  function encodeNegint(writer, token) {
    const negint = token.value;
    const unsigned = typeof negint === "bigint" ? negint * neg1b - pos1b : negint * -1 - 1;
    encodeUintValue(writer, token.type.majorEncoded, unsigned);
  }
  encodeNegint.encodedSize = function encodedSize3(token) {
    const negint = token.value;
    const unsigned = typeof negint === "bigint" ? negint * neg1b - pos1b : negint * -1 - 1;
    if (unsigned < uintBoundaries[0]) {
      return 1;
    }
    if (unsigned < uintBoundaries[1]) {
      return 2;
    }
    if (unsigned < uintBoundaries[2]) {
      return 3;
    }
    if (unsigned < uintBoundaries[3]) {
      return 5;
    }
    return 9;
  };
  encodeNegint.compareTokens = function compareTokens2(tok1, tok2) {
    return tok1.value < tok2.value ? 1 : tok1.value > tok2.value ? -1 : 0;
  };

  // node_modules/cborg/lib/2bytes.js
  function toToken(data, pos, prefix, length) {
    assertEnoughData(data, pos, prefix + length);
    const buf = data.slice(pos + prefix, pos + prefix + length);
    return new Token(Type.bytes, buf, prefix + length);
  }
  function decodeBytesCompact(data, pos, minor, _options) {
    return toToken(data, pos, 1, minor);
  }
  function decodeBytes8(data, pos, _minor, options) {
    return toToken(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeBytes16(data, pos, _minor, options) {
    return toToken(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeBytes32(data, pos, _minor, options) {
    return toToken(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeBytes64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer bytes lengths not supported`);
    }
    return toToken(data, pos, 9, l);
  }
  function tokenBytes(token) {
    if (token.encodedBytes === undefined) {
      token.encodedBytes = Type.equals(token.type, Type.string) ? fromString(token.value) : token.value;
    }
    return token.encodedBytes;
  }
  function encodeBytes(writer, token) {
    const bytes = tokenBytes(token);
    encodeUintValue(writer, token.type.majorEncoded, bytes.length);
    writer.push(bytes);
  }
  encodeBytes.encodedSize = function encodedSize4(token) {
    const bytes = tokenBytes(token);
    return encodeUintValue.encodedSize(bytes.length) + bytes.length;
  };
  encodeBytes.compareTokens = function compareTokens3(tok1, tok2) {
    return compareBytes(tokenBytes(tok1), tokenBytes(tok2));
  };
  function compareBytes(b1, b2) {
    return b1.length < b2.length ? -1 : b1.length > b2.length ? 1 : compare(b1, b2);
  }

  // node_modules/cborg/lib/3string.js
  var textDecoder = new TextDecoder;
  var ASCII_THRESHOLD = 32;
  function toStr(bytes, start, end) {
    const len = end - start;
    if (len < ASCII_THRESHOLD) {
      let str = "";
      for (let i = start;i < end; i++) {
        const c = bytes[i];
        if (c & 128) {
          return textDecoder.decode(bytes.subarray(start, end));
        }
        str += String.fromCharCode(c);
      }
      return str;
    }
    return textDecoder.decode(bytes.subarray(start, end));
  }
  function toToken2(data, pos, prefix, length, options) {
    const totLength = prefix + length;
    assertEnoughData(data, pos, totLength);
    const tok = new Token(Type.string, toStr(data, pos + prefix, pos + totLength), totLength);
    if (options.retainStringBytes === true) {
      tok.byteValue = data.slice(pos + prefix, pos + totLength);
    }
    return tok;
  }
  function decodeStringCompact(data, pos, minor, options) {
    return toToken2(data, pos, 1, minor, options);
  }
  function decodeString8(data, pos, _minor, options) {
    return toToken2(data, pos, 2, readUint8(data, pos + 1, options), options);
  }
  function decodeString16(data, pos, _minor, options) {
    return toToken2(data, pos, 3, readUint16(data, pos + 1, options), options);
  }
  function decodeString32(data, pos, _minor, options) {
    return toToken2(data, pos, 5, readUint32(data, pos + 1, options), options);
  }
  function decodeString64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer string lengths not supported`);
    }
    return toToken2(data, pos, 9, l, options);
  }
  var encodeString = encodeBytes;

  // node_modules/cborg/lib/4array.js
  function toToken3(_data, _pos, prefix, length) {
    return new Token(Type.array, length, prefix);
  }
  function decodeArrayCompact(data, pos, minor, _options) {
    return toToken3(data, pos, 1, minor);
  }
  function decodeArray8(data, pos, _minor, options) {
    return toToken3(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeArray16(data, pos, _minor, options) {
    return toToken3(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeArray32(data, pos, _minor, options) {
    return toToken3(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeArray64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer array lengths not supported`);
    }
    return toToken3(data, pos, 9, l);
  }
  function decodeArrayIndefinite(data, pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return toToken3(data, pos, 1, Infinity);
  }
  function encodeArray(writer, token) {
    encodeUintValue(writer, Type.array.majorEncoded, token.value);
  }
  encodeArray.compareTokens = encodeUint.compareTokens;
  encodeArray.encodedSize = function encodedSize5(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/5map.js
  function toToken4(_data, _pos, prefix, length) {
    return new Token(Type.map, length, prefix);
  }
  function decodeMapCompact(data, pos, minor, _options) {
    return toToken4(data, pos, 1, minor);
  }
  function decodeMap8(data, pos, _minor, options) {
    return toToken4(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeMap16(data, pos, _minor, options) {
    return toToken4(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeMap32(data, pos, _minor, options) {
    return toToken4(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeMap64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer map lengths not supported`);
    }
    return toToken4(data, pos, 9, l);
  }
  function decodeMapIndefinite(data, pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return toToken4(data, pos, 1, Infinity);
  }
  function encodeMap(writer, token) {
    encodeUintValue(writer, Type.map.majorEncoded, token.value);
  }
  encodeMap.compareTokens = encodeUint.compareTokens;
  encodeMap.encodedSize = function encodedSize6(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/6tag.js
  function decodeTagCompact(_data, _pos, minor, _options) {
    return new Token(Type.tag, minor, 1);
  }
  function decodeTag8(data, pos, _minor, options) {
    return new Token(Type.tag, readUint8(data, pos + 1, options), 2);
  }
  function decodeTag16(data, pos, _minor, options) {
    return new Token(Type.tag, readUint16(data, pos + 1, options), 3);
  }
  function decodeTag32(data, pos, _minor, options) {
    return new Token(Type.tag, readUint32(data, pos + 1, options), 5);
  }
  function decodeTag64(data, pos, _minor, options) {
    return new Token(Type.tag, readUint64(data, pos + 1, options), 9);
  }
  function encodeTag(writer, token) {
    encodeUintValue(writer, Type.tag.majorEncoded, token.value);
  }
  encodeTag.compareTokens = encodeUint.compareTokens;
  encodeTag.encodedSize = function encodedSize7(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/7float.js
  var MINOR_FALSE = 20;
  var MINOR_TRUE = 21;
  var MINOR_NULL = 22;
  var MINOR_UNDEFINED = 23;
  function decodeUndefined(_data, _pos, _minor, options) {
    if (options.allowUndefined === false) {
      throw new Error(`${decodeErrPrefix} undefined values are not supported`);
    } else if (options.coerceUndefinedToNull === true) {
      return new Token(Type.null, null, 1);
    }
    return new Token(Type.undefined, undefined, 1);
  }
  function decodeBreak(_data, _pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return new Token(Type.break, undefined, 1);
  }
  function createToken(value, bytes, options) {
    if (options) {
      if (options.allowNaN === false && Number.isNaN(value)) {
        throw new Error(`${decodeErrPrefix} NaN values are not supported`);
      }
      if (options.allowInfinity === false && (value === Infinity || value === -Infinity)) {
        throw new Error(`${decodeErrPrefix} Infinity values are not supported`);
      }
    }
    return new Token(Type.float, value, bytes);
  }
  function decodeFloat16(data, pos, _minor, options) {
    return createToken(readFloat16(data, pos + 1), 3, options);
  }
  function decodeFloat32(data, pos, _minor, options) {
    return createToken(readFloat32(data, pos + 1), 5, options);
  }
  function decodeFloat64(data, pos, _minor, options) {
    return createToken(readFloat64(data, pos + 1), 9, options);
  }
  function encodeFloat(writer, token, options) {
    const float = token.value;
    if (float === false) {
      writer.pushByte(Type.float.majorEncoded | MINOR_FALSE);
    } else if (float === true) {
      writer.pushByte(Type.float.majorEncoded | MINOR_TRUE);
    } else if (float === null) {
      writer.pushByte(Type.float.majorEncoded | MINOR_NULL);
    } else if (float === undefined) {
      writer.pushByte(Type.float.majorEncoded | MINOR_UNDEFINED);
    } else {
      let decoded;
      let success = false;
      if (!options || options.float64 !== true) {
        encodeFloat16(float);
        decoded = readFloat16(ui8a, 1);
        if (float === decoded || Number.isNaN(float)) {
          ui8a[0] = 249;
          writer.push(ui8a.slice(0, 3));
          success = true;
        } else {
          encodeFloat32(float);
          decoded = readFloat32(ui8a, 1);
          if (float === decoded) {
            ui8a[0] = 250;
            writer.push(ui8a.slice(0, 5));
            success = true;
          }
        }
      }
      if (!success) {
        encodeFloat64(float);
        decoded = readFloat64(ui8a, 1);
        ui8a[0] = 251;
        writer.push(ui8a.slice(0, 9));
      }
    }
  }
  encodeFloat.encodedSize = function encodedSize8(token, options) {
    const float = token.value;
    if (float === false || float === true || float === null || float === undefined) {
      return 1;
    }
    if (!options || options.float64 !== true) {
      encodeFloat16(float);
      let decoded = readFloat16(ui8a, 1);
      if (float === decoded || Number.isNaN(float)) {
        return 3;
      }
      encodeFloat32(float);
      decoded = readFloat32(ui8a, 1);
      if (float === decoded) {
        return 5;
      }
    }
    return 9;
  };
  var buffer = new ArrayBuffer(9);
  var dataView = new DataView(buffer, 1);
  var ui8a = new Uint8Array(buffer, 0);
  function encodeFloat16(inp) {
    if (inp === Infinity) {
      dataView.setUint16(0, 31744, false);
    } else if (inp === -Infinity) {
      dataView.setUint16(0, 64512, false);
    } else if (Number.isNaN(inp)) {
      dataView.setUint16(0, 32256, false);
    } else {
      dataView.setFloat32(0, inp);
      const valu32 = dataView.getUint32(0);
      const exponent = (valu32 & 2139095040) >> 23;
      const mantissa = valu32 & 8388607;
      if (exponent === 255) {
        dataView.setUint16(0, 31744, false);
      } else if (exponent === 0) {
        dataView.setUint16(0, (valu32 & 2147483648) >> 16 | mantissa >> 13, false);
      } else {
        const logicalExponent = exponent - 127;
        if (logicalExponent < -24) {
          dataView.setUint16(0, 0);
        } else if (logicalExponent < -14) {
          dataView.setUint16(0, (valu32 & 2147483648) >> 16 | 1 << 24 + logicalExponent, false);
        } else {
          dataView.setUint16(0, (valu32 & 2147483648) >> 16 | logicalExponent + 15 << 10 | mantissa >> 13, false);
        }
      }
    }
  }
  function readFloat16(ui8a2, pos) {
    if (ui8a2.length - pos < 2) {
      throw new Error(`${decodeErrPrefix} not enough data for float16`);
    }
    const half = (ui8a2[pos] << 8) + ui8a2[pos + 1];
    if (half === 31744) {
      return Infinity;
    }
    if (half === 64512) {
      return -Infinity;
    }
    if (half === 32256) {
      return NaN;
    }
    const exp = half >> 10 & 31;
    const mant = half & 1023;
    let val;
    if (exp === 0) {
      val = mant * 2 ** -24;
    } else if (exp !== 31) {
      val = (mant + 1024) * 2 ** (exp - 25);
    } else {
      val = mant === 0 ? Infinity : NaN;
    }
    return half & 32768 ? -val : val;
  }
  function encodeFloat32(inp) {
    dataView.setFloat32(0, inp, false);
  }
  function readFloat32(ui8a2, pos) {
    if (ui8a2.length - pos < 4) {
      throw new Error(`${decodeErrPrefix} not enough data for float32`);
    }
    const offset = (ui8a2.byteOffset || 0) + pos;
    return new DataView(ui8a2.buffer, offset, 4).getFloat32(0, false);
  }
  function encodeFloat64(inp) {
    dataView.setFloat64(0, inp, false);
  }
  function readFloat64(ui8a2, pos) {
    if (ui8a2.length - pos < 8) {
      throw new Error(`${decodeErrPrefix} not enough data for float64`);
    }
    const offset = (ui8a2.byteOffset || 0) + pos;
    return new DataView(ui8a2.buffer, offset, 8).getFloat64(0, false);
  }
  function encodeMajorSevenBytes(token, float64) {
    const float = token.value;
    if (float === false) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_FALSE);
    }
    if (float === true) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_TRUE);
    }
    if (float === null) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_NULL);
    }
    if (float === undefined) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_UNDEFINED);
    }
    if (!float64) {
      encodeFloat16(float);
      if (float === readFloat16(ui8a, 1) || Number.isNaN(float)) {
        ui8a[0] = 249;
        return ui8a.slice(0, 3);
      }
      encodeFloat32(float);
      if (float === readFloat32(ui8a, 1)) {
        ui8a[0] = 250;
        return ui8a.slice(0, 5);
      }
    }
    encodeFloat64(float);
    ui8a[0] = 251;
    return ui8a.slice(0, 9);
  }
  function majorSevenBytes(token, options) {
    const tokenEx = token;
    const float64 = options?.float64 === true;
    const cached = float64 ? tokenEx._keyBytesFloat64 : tokenEx._keyBytes;
    if (cached !== undefined) {
      return cached;
    }
    const bytes = encodeMajorSevenBytes(token, float64);
    if (float64) {
      tokenEx._keyBytesFloat64 = bytes;
    } else {
      tokenEx._keyBytes = bytes;
    }
    return bytes;
  }
  encodeFloat.compareTokens = function compareTokens4(tok1, tok2, options) {
    const b1 = majorSevenBytes(tok1, options);
    const b2 = majorSevenBytes(tok2, options);
    if (b1.length !== b2.length) {
      return b1.length < b2.length ? -1 : 1;
    }
    return compare(b1, b2);
  };

  // node_modules/cborg/lib/jump.js
  function invalidMinor(data, pos, minor) {
    throw new Error(`${decodeErrPrefix} encountered invalid minor (${minor}) for major ${data[pos] >>> 5}`);
  }
  function errorer(msg) {
    return () => {
      throw new Error(`${decodeErrPrefix} ${msg}`);
    };
  }
  var jump = [];
  for (let i = 0;i <= 23; i++) {
    jump[i] = invalidMinor;
  }
  jump[24] = decodeUint8;
  jump[25] = decodeUint16;
  jump[26] = decodeUint32;
  jump[27] = decodeUint64;
  jump[28] = invalidMinor;
  jump[29] = invalidMinor;
  jump[30] = invalidMinor;
  jump[31] = invalidMinor;
  for (let i = 32;i <= 55; i++) {
    jump[i] = invalidMinor;
  }
  jump[56] = decodeNegint8;
  jump[57] = decodeNegint16;
  jump[58] = decodeNegint32;
  jump[59] = decodeNegint64;
  jump[60] = invalidMinor;
  jump[61] = invalidMinor;
  jump[62] = invalidMinor;
  jump[63] = invalidMinor;
  for (let i = 64;i <= 87; i++) {
    jump[i] = decodeBytesCompact;
  }
  jump[88] = decodeBytes8;
  jump[89] = decodeBytes16;
  jump[90] = decodeBytes32;
  jump[91] = decodeBytes64;
  jump[92] = invalidMinor;
  jump[93] = invalidMinor;
  jump[94] = invalidMinor;
  jump[95] = errorer("indefinite length bytes/strings are not supported");
  for (let i = 96;i <= 119; i++) {
    jump[i] = decodeStringCompact;
  }
  jump[120] = decodeString8;
  jump[121] = decodeString16;
  jump[122] = decodeString32;
  jump[123] = decodeString64;
  jump[124] = invalidMinor;
  jump[125] = invalidMinor;
  jump[126] = invalidMinor;
  jump[127] = errorer("indefinite length bytes/strings are not supported");
  for (let i = 128;i <= 151; i++) {
    jump[i] = decodeArrayCompact;
  }
  jump[152] = decodeArray8;
  jump[153] = decodeArray16;
  jump[154] = decodeArray32;
  jump[155] = decodeArray64;
  jump[156] = invalidMinor;
  jump[157] = invalidMinor;
  jump[158] = invalidMinor;
  jump[159] = decodeArrayIndefinite;
  for (let i = 160;i <= 183; i++) {
    jump[i] = decodeMapCompact;
  }
  jump[184] = decodeMap8;
  jump[185] = decodeMap16;
  jump[186] = decodeMap32;
  jump[187] = decodeMap64;
  jump[188] = invalidMinor;
  jump[189] = invalidMinor;
  jump[190] = invalidMinor;
  jump[191] = decodeMapIndefinite;
  for (let i = 192;i <= 215; i++) {
    jump[i] = decodeTagCompact;
  }
  jump[216] = decodeTag8;
  jump[217] = decodeTag16;
  jump[218] = decodeTag32;
  jump[219] = decodeTag64;
  jump[220] = invalidMinor;
  jump[221] = invalidMinor;
  jump[222] = invalidMinor;
  jump[223] = invalidMinor;
  for (let i = 224;i <= 243; i++) {
    jump[i] = errorer("simple values are not supported");
  }
  jump[244] = invalidMinor;
  jump[245] = invalidMinor;
  jump[246] = invalidMinor;
  jump[247] = decodeUndefined;
  jump[248] = errorer("simple values are not supported");
  jump[249] = decodeFloat16;
  jump[250] = decodeFloat32;
  jump[251] = decodeFloat64;
  jump[252] = invalidMinor;
  jump[253] = invalidMinor;
  jump[254] = invalidMinor;
  jump[255] = decodeBreak;
  var quick = [];
  for (let i = 0;i < 24; i++) {
    quick[i] = new Token(Type.uint, i, 1);
  }
  for (let i = -1;i >= -24; i--) {
    quick[31 - i] = new Token(Type.negint, i, 1);
  }
  quick[64] = new Token(Type.bytes, new Uint8Array(0), 1);
  quick[96] = new Token(Type.string, "", 1);
  quick[128] = new Token(Type.array, 0, 1);
  quick[160] = new Token(Type.map, 0, 1);
  quick[244] = new Token(Type.false, false, 1);
  quick[245] = new Token(Type.true, true, 1);
  quick[246] = new Token(Type.null, null, 1);
  function quickEncodeToken(token) {
    switch (token.type) {
      case Type.false:
        return fromArray([244]);
      case Type.true:
        return fromArray([245]);
      case Type.null:
        return fromArray([246]);
      case Type.bytes:
        if (!token.value.length) {
          return fromArray([64]);
        }
        return;
      case Type.string:
        if (token.value === "") {
          return fromArray([96]);
        }
        return;
      case Type.array:
        if (token.value === 0) {
          return fromArray([128]);
        }
        return;
      case Type.map:
        if (token.value === 0) {
          return fromArray([160]);
        }
        return;
      case Type.uint:
        if (token.value < 24) {
          return fromArray([Number(token.value)]);
        }
        return;
      case Type.negint:
        if (token.value >= -24) {
          return fromArray([31 - Number(token.value)]);
        }
    }
  }

  // node_modules/cborg/lib/encode.js
  var rfc8949EncodeOptions = Object.freeze({
    mapSorter: rfc8949MapSorter,
    quickEncodeToken
  });
  function makeCborEncoders() {
    const encoders = [];
    encoders[Type.uint.major] = encodeUint;
    encoders[Type.negint.major] = encodeNegint;
    encoders[Type.bytes.major] = encodeBytes;
    encoders[Type.string.major] = encodeString;
    encoders[Type.array.major] = encodeArray;
    encoders[Type.map.major] = encodeMap;
    encoders[Type.tag.major] = encodeTag;
    encoders[Type.float.major] = encodeFloat;
    return encoders;
  }
  var cborEncoders = makeCborEncoders();
  var defaultWriter = new Bl;

  class Ref {
    constructor(obj, parent) {
      this.obj = obj;
      this.parent = parent;
    }
    includes(obj) {
      let p = this;
      do {
        if (p.obj === obj) {
          return true;
        }
      } while (p = p.parent);
      return false;
    }
    static createCheck(stack, obj) {
      if (stack && stack.includes(obj)) {
        throw new Error(`${encodeErrPrefix} object contains circular references`);
      }
      return new Ref(obj, stack);
    }
  }
  var simpleTokens = {
    null: new Token(Type.null, null),
    undefined: new Token(Type.undefined, undefined),
    true: new Token(Type.true, true),
    false: new Token(Type.false, false),
    emptyArray: new Token(Type.array, 0),
    emptyMap: new Token(Type.map, 0)
  };
  var typeEncoders = {
    number(obj, _typ, _options, _refStack) {
      if (!Number.isInteger(obj) || !Number.isSafeInteger(obj)) {
        return new Token(Type.float, obj);
      } else if (obj >= 0) {
        return new Token(Type.uint, obj);
      } else {
        return new Token(Type.negint, obj);
      }
    },
    bigint(obj, _typ, _options, _refStack) {
      if (obj >= BigInt(0)) {
        return new Token(Type.uint, obj);
      } else {
        return new Token(Type.negint, obj);
      }
    },
    Uint8Array(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, obj);
    },
    string(obj, _typ, _options, _refStack) {
      return new Token(Type.string, obj);
    },
    boolean(obj, _typ, _options, _refStack) {
      return obj ? simpleTokens.true : simpleTokens.false;
    },
    null(_obj, _typ, _options, _refStack) {
      return simpleTokens.null;
    },
    undefined(_obj, _typ, _options, _refStack) {
      return simpleTokens.undefined;
    },
    ArrayBuffer(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, new Uint8Array(obj));
    },
    DataView(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength));
    },
    Array(obj, _typ, options, refStack) {
      if (!obj.length) {
        if (options.addBreakTokens === true) {
          return [simpleTokens.emptyArray, new Token(Type.break)];
        }
        return simpleTokens.emptyArray;
      }
      refStack = Ref.createCheck(refStack, obj);
      const entries = [];
      let i = 0;
      for (const e of obj) {
        entries[i++] = objectToTokens(e, options, refStack);
      }
      if (options.addBreakTokens) {
        return [new Token(Type.array, obj.length), entries, new Token(Type.break)];
      }
      return [new Token(Type.array, obj.length), entries];
    },
    Object(obj, typ, options, refStack) {
      const isMap = typ !== "Object";
      const keys = isMap ? obj.keys() : Object.keys(obj);
      const maxLength = isMap ? obj.size : keys.length;
      let entries;
      if (maxLength) {
        entries = new Array(maxLength);
        refStack = Ref.createCheck(refStack, obj);
        const skipUndefined = !isMap && options.ignoreUndefinedProperties;
        let i = 0;
        for (const key of keys) {
          const value = isMap ? obj.get(key) : obj[key];
          if (skipUndefined && value === undefined) {
            continue;
          }
          entries[i++] = [
            objectToTokens(key, options, refStack),
            objectToTokens(value, options, refStack)
          ];
        }
        if (i < maxLength) {
          entries.length = i;
        }
      }
      if (!entries?.length) {
        if (options.addBreakTokens === true) {
          return [simpleTokens.emptyMap, new Token(Type.break)];
        }
        return simpleTokens.emptyMap;
      }
      sortMapEntries(entries, options);
      if (options.addBreakTokens) {
        return [new Token(Type.map, entries.length), entries, new Token(Type.break)];
      }
      return [new Token(Type.map, entries.length), entries];
    },
    Tagged(obj, _typ, options, refStack) {
      return [
        new Token(Type.tag, obj.tag),
        objectToTokens(obj.value, options, refStack)
      ];
    }
  };
  typeEncoders.Map = typeEncoders.Object;
  typeEncoders.Buffer = typeEncoders.Uint8Array;
  for (const typ of "Uint8Clamped Uint16 Uint32 Int8 Int16 Int32 BigUint64 BigInt64 Float32 Float64".split(" ")) {
    typeEncoders[`${typ}Array`] = typeEncoders.DataView;
  }
  function objectToTokens(obj, options = {}, refStack) {
    const typ = is(obj);
    const customTypeEncoder = options && options.typeEncoders && options.typeEncoders[typ] || typeEncoders[typ];
    if (typeof customTypeEncoder === "function") {
      const tokens = customTypeEncoder(obj, typ, options, refStack);
      if (tokens != null) {
        return tokens;
      }
    }
    const typeEncoder = typeEncoders[typ];
    if (!typeEncoder) {
      throw new Error(`${encodeErrPrefix} unsupported type: ${typ}`);
    }
    return typeEncoder(obj, typ, options, refStack);
  }
  function sortMapEntries(entries, options) {
    const mapSorter = options.mapSorter;
    if (mapSorter) {
      entries.sort((e1, e2) => mapSorter(e1, e2, options));
    }
  }
  function rfc8949MapSorter(e1, e2) {
    if (e1[0] instanceof Token && e2[0] instanceof Token) {
      const t1 = e1[0];
      const t2 = e2[0];
      if (!t1._keyBytes) {
        t1._keyBytes = encodeRfc8949(t1.value);
      }
      if (!t2._keyBytes) {
        t2._keyBytes = encodeRfc8949(t2.value);
      }
      return compare(t1._keyBytes, t2._keyBytes);
    }
    throw new Error("rfc8949MapSorter: complex key types are not supported yet");
  }
  function encodeRfc8949(data) {
    return encodeCustom(data, cborEncoders, rfc8949EncodeOptions);
  }
  function tokensToEncoded(writer, tokens, encoders, options) {
    if (Array.isArray(tokens)) {
      for (const token of tokens) {
        tokensToEncoded(writer, token, encoders, options);
      }
    } else {
      encoders[tokens.type.major](writer, tokens, options);
    }
  }
  var MAJOR_UINT = Type.uint.majorEncoded;
  var MAJOR_NEGINT = Type.negint.majorEncoded;
  var MAJOR_BYTES = Type.bytes.majorEncoded;
  var MAJOR_STRING = Type.string.majorEncoded;
  var MAJOR_ARRAY = Type.array.majorEncoded;
  var MAJOR_MAP = Type.map.majorEncoded;
  var SIMPLE_FALSE = Type.float.majorEncoded | MINOR_FALSE;
  var SIMPLE_TRUE = Type.float.majorEncoded | MINOR_TRUE;
  var SIMPLE_NULL = Type.float.majorEncoded | MINOR_NULL;
  var SIMPLE_UNDEFINED = Type.float.majorEncoded | MINOR_UNDEFINED;
  var neg1b2 = BigInt(-1);
  var pos1b2 = BigInt(1);
  function encodeCustom(data, encoders, options, destination) {
    const hasDest = destination instanceof Uint8Array;
    let writeTo = hasDest ? new U8Bl(destination) : defaultWriter;
    const tokens = objectToTokens(data, options);
    if (!Array.isArray(tokens) && options.quickEncodeToken) {
      const quickBytes = options.quickEncodeToken(tokens);
      if (quickBytes) {
        if (hasDest) {
          writeTo.push(quickBytes);
          return writeTo.toBytes();
        }
        return quickBytes;
      }
      const encoder2 = encoders[tokens.type.major];
      if (encoder2.encodedSize) {
        const size = encoder2.encodedSize(tokens, options);
        if (!hasDest) {
          writeTo = new Bl(size);
        }
        encoder2(writeTo, tokens, options);
        if (writeTo.chunks.length !== 1) {
          throw new Error(`Unexpected error: pre-calculated length for ${tokens} was wrong`);
        }
        return hasDest ? writeTo.toBytes() : asU8A(writeTo.chunks[0]);
      }
    }
    writeTo.reset();
    tokensToEncoded(writeTo, tokens, encoders, options);
    return writeTo.toBytes(true);
  }

  // node_modules/cborg/lib/decode.js
  var DONE = Symbol.for("DONE");
  var BREAK = Symbol.for("BREAK");

  // node_modules/cborg/lib/tagged.js
  class Tagged {
    constructor(tag, value) {
      if (typeof tag !== "number" || !Number.isInteger(tag) || tag < 0) {
        throw new TypeError("Tagged: tag must be a non-negative integer");
      }
      this.tag = tag;
      this.value = value;
    }
    static decoder(tag) {
      return (decode) => new Tagged(tag, decode());
    }
    static preserve(...tagNumbers) {
      const tags = {};
      for (const tag of tagNumbers) {
        tags[tag] = Tagged.decoder(tag);
      }
      return tags;
    }
  }
  Object.defineProperty(Tagged.prototype, Symbol.toStringTag, {
    value: "Tagged"
  });

  // node_modules/@action-state-group/cll/dist/chunk-BW57WVJQ.js
  var ok = (x) => x.length === 32;
  var same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  var be64 = (n) => {
    const x = new Uint8Array(8);
    new DataView(x.buffer).setBigUint64(0, n);
    return x;
  };
  var parent = (hash, l, r, p) => hash(be64(BigInt(p + 1)), l, r);
  var hex = (x) => /^[0-9a-f]{64}$/u.test(x) ? Uint8Array.from(x.match(/../gu), (b) => Number.parseInt(b, 16)) : undefined;
  function shape(leaves) {
    const meta = [], peaks = [], positions = [];
    for (let i = 0;i < leaves; i += 1) {
      let p = meta.length;
      meta.push({ height: 0 });
      positions.push(p);
      while (peaks.length && meta[peaks.at(-1)].height === meta[p].height) {
        const l = peaks.pop(), q = meta.length;
        meta.push({ height: meta[p].height + 1, left: l, right: p });
        meta[l].parent = q;
        meta[p].parent = q;
        p = q;
      }
      peaks.push(p);
    }
    return { meta, peaks, leaves: positions };
  }
  function leafCount(size) {
    if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER))
      return;
    const count = (n) => 2n * n - BigInt(n.toString(2).replaceAll("0", "").length);
    let lo = 0n, hi = size + 1n;
    while (lo <= hi) {
      const n = lo + hi >> 1n, c = count(n);
      if (c === size)
        return n;
      if (c < size)
        lo = n + 1n;
      else
        hi = n - 1n;
    }
    return;
  }
  async function rootFromPeaks(hash, peaks) {
    if (!peaks.length)
      return new Uint8Array(32);
    let root = Uint8Array.from(peaks.at(-1));
    for (let i = peaks.length - 2;i >= 0; i -= 1)
      root = await hash(root, peaks[i]);
    return root;
  }
  async function verifyInclusionValue(hash, root, size, leafIndex, value, proof) {
    const leaves = leafCount(size);
    if (!ok(root) || !ok(value) || leaves === undefined || leafIndex < 0n || leafIndex >= leaves || proof.some((x) => !ok(x)))
      return false;
    const s = shape(Number(leaves)), leaf = s.leaves[Number(leafIndex)];
    let p = leaf, v = await hash(Uint8Array.of(0), value), i = 0;
    while (s.meta[p].parent !== undefined) {
      const q = s.meta[p].parent, m = s.meta[q], x = proof[i++];
      if (!x)
        return false;
      v = m.left === p ? await parent(hash, v, x, q) : await parent(hash, x, v, q);
      p = q;
    }
    const peak = s.peaks.indexOf(p);
    if (peak < s.peaks.length - 1) {
      const right = proof[i++];
      if (!right)
        return false;
      v = await hash(right, v);
    }
    for (let left = peak - 1;left >= 0; left -= 1) {
      const item = proof[i++];
      if (!item)
        return false;
      v = await hash(v, item);
    }
    return i === proof.length && same(v, root);
  }
  async function verifyHexInclusion(hash, root, size, leafIndex, identity, proof) {
    const value = hex(identity);
    return value !== undefined && verifyInclusionValue(hash, root, size, leafIndex, value, proof);
  }

  // node_modules/@action-state-group/cll/dist/browser.js
  var join = (...parts) => {
    const value = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) {
      value.set(part, offset);
      offset += part.length;
    }
    return value;
  };
  var hash = async (...parts) => new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", join(...parts)));
  var rootFromPeaks2 = (peaks) => rootFromPeaks(hash, peaks);
  var verifyHexInclusion2 = (root, size, leafIndex, identity, proof) => verifyHexInclusion(hash, root, size, leafIndex, identity, proof);

  // node_modules/@action-state-group/agent-action-capsule/dist/disclosure-path.js
  function resolveDisclosurePath(root, path) {
    let value = root;
    for (const member of path.split(".")) {
      if (member === "")
        return;
      value = asJsonObject(value)?.[member];
      if (value === undefined)
        return;
    }
    return value;
  }

  // node_modules/@action-state-group/agent-action-capsule/dist/disclosure-envelope.js
  var DISCLOSURE_MATCH = "disclosure_match";
  var DISCLOSURE_MISMATCH = "disclosure_mismatch";
  var DISCLOSURE_INELIGIBLE_FIELD = "disclosure_ineligible_field";
  var DISCLOSURE_NO_COMMITTED_DIGEST = "disclosure_no_committed_digest";
  async function verifyDisclosureEnvelope(envelope) {
    const wrapper = asJsonObject(envelope);
    const capsule = wrapper?.capsule ?? envelope;
    const capsuleResult = await verifyClass1(capsule);
    const disclosures = asJsonObject(wrapper?.disclosures);
    const findings = [];
    const capsuleObject = asJsonObject(capsule);
    if (disclosures !== undefined) {
      for (const [member, value] of Object.entries(disclosures).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
        const path = disclosureEligibleFields[member];
        if (path === undefined) {
          findings.push({ member, code: DISCLOSURE_INELIGIBLE_FIELD });
          continue;
        }
        const committed = capsuleObject === undefined ? undefined : resolveDisclosurePath(capsuleObject, path);
        if (typeof committed !== "string" || !/^[0-9a-f]{64}$/u.test(committed)) {
          findings.push({ member, code: DISCLOSURE_NO_COMMITTED_DIGEST });
          continue;
        }
        let matches = false;
        try {
          const computed = await jsonDigest(value);
          matches = computed === committed;
        } catch {
          matches = false;
        }
        findings.push({
          member,
          code: matches ? DISCLOSURE_MATCH : DISCLOSURE_MISMATCH
        });
      }
    }
    const matched = findings.filter((finding) => finding.code === DISCLOSURE_MATCH).length;
    return {
      ok: capsuleResult.ok && findings.every((finding) => finding.code === DISCLOSURE_MATCH),
      capsuleResult,
      disclosuresChecked: findings.length,
      disclosuresMatched: matched,
      disclosureFindings: findings
    };
  }

  // node_modules/@action-state-group/agent-action-capsule/dist/bundle.js
  var text = new TextDecoder("utf-8", { fatal: true });
  var pass = () => ({ status: "pass", findings: [] });
  var fail = (...findings) => ({
    status: "fail",
    findings
  });
  var object2 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  var integer = (value) => typeof value === "number" && Number.isSafeInteger(value);
  var hex2 = (value) => Uint8Array.from(value.match(/../gu), (byte) => Number.parseInt(byte, 16));
  function encodeFragment(bundle) {
    return btoa(Array.from(jcs(bundle), (byte) => String.fromCharCode(byte)).join("")).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }
  function decodeFragment(fragment) {
    if (!/^[A-Za-z0-9_-]*$/u.test(fragment))
      throw new TypeError("fragment base64url");
    try {
      const padded = `${fragment}${"=".repeat((4 - fragment.length % 4) % 4)}`;
      const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
      const value = JSON.parse(text.decode(Uint8Array.from(binary, (char) => char.charCodeAt(0))));
      if (!object2(value))
        throw new TypeError("bundle JSON object");
      return value;
    } catch (error) {
      if (error instanceof TypeError && error.message === "bundle JSON object")
        throw error;
      throw new TypeError("fragment UTF-8 JSON");
    }
  }
  async function bundleDigest(bundle) {
    return sha256Hex(jcs(Object.fromEntries(Object.entries(bundle).filter(([key]) => key !== "countersignatures"))));
  }
  async function verifyBundle(bundle) {
    const invalid = fail("bundle_malformed");
    if (!object2(bundle))
      return {
        graphClosure: invalid,
        intervalCoverage: invalid,
        perRecordMembership: invalid,
        disclosures: [],
        extensions: [],
        countersignatures: [],
        capsuleResults: {}
      };
    let digest;
    try {
      digest = await bundleDigest(bundle);
    } catch {}
    const collected = await collectRecords(bundle.records);
    const [intervalCoverage, perRecordMembership] = await completeness(bundle, collected.records);
    return {
      ...digest === undefined ? {} : { bundleDigest: digest },
      graphClosure: graph(bundle, collected.records, collected.findings),
      intervalCoverage,
      perRecordMembership,
      disclosures: await disclosures(bundle.disclosures, collected.records),
      extensions: extensions(bundle.extensions),
      countersignatures: Array.isArray(bundle.countersignatures) ? bundle.countersignatures : [],
      capsuleResults: collected.results
    };
  }
  async function collectRecords(raw) {
    const records = new Map, results = {}, findings = [];
    if (!Array.isArray(raw))
      return { records, results, findings: ["records_malformed"] };
    for (const [index, record] of raw.entries()) {
      if (!object2(record)) {
        findings.push(`record_malformed:${index}`);
        continue;
      }
      const id = record.capsule_id;
      if (!isHex64(id)) {
        findings.push(`record_identity_invalid:${index}`);
        continue;
      }
      if (records.has(id)) {
        findings.push(`record_duplicate:${id}`);
        continue;
      }
      const result = await verifyClass1(record);
      results[id] = result;
      if (!result.ok || result.capsuleId !== id) {
        findings.push(`record_identity_invalid:${id}`);
        continue;
      }
      records.set(id, record);
    }
    return { records, results, findings };
  }
  function graph(bundle, records, recordFindings) {
    const findings = [...recordFindings];
    if (bundle.bundle_version !== "2" || bundle.bundle_kind !== "evidence-bundle/v2")
      findings.push("bundle_version_or_kind_invalid");
    const root = bundle.root;
    if (!isHex64(root) || !records.has(root))
      return fail(...findings, "root_not_supplied_with_matching_identity");
    const complete = bundle.completeness;
    if (!object2(complete))
      return fail(...findings, "completeness_malformed");
    const depth = complete.closure_depth ?? 2;
    if (!integer(depth) || depth < 0)
      return fail(...findings, "closure_depth_invalid");
    const missingRaw = complete.missing ?? [];
    if (!Array.isArray(missingRaw) || missingRaw.some((id) => !isHex64(id)))
      return fail(...findings, "missing_malformed");
    const missing = new Set(missingRaw);
    if (missing.size !== missingRaw.length)
      findings.push("missing_duplicate");
    if (complete.records_mode !== (missing.size ? "declared_incomplete" : "complete"))
      findings.push("records_mode_mismatch");
    let frontier = [root];
    for (let level = 0;level < depth; level += 1) {
      const next = [];
      for (const source of frontier)
        for (const target of citations(records.get(source)))
          if (records.has(target))
            next.push(target);
          else if (!missing.has(target))
            findings.push(`citation_dangling:${target}`);
      frontier = next;
    }
    return findings.length ? fail(...findings) : missing.size ? { status: "withheld", findings: ["declared_incomplete"] } : pass();
  }
  function citations(record) {
    const targets = [], chain = record.chain;
    if (object2(chain) && typeof chain.parent_capsule_id === "string")
      targets.push(chain.parent_capsule_id);
    if (Array.isArray(record.references)) {
      for (const reference of record.references)
        if (object2(reference) && reference.type === "agent-action-capsule" && reference.digest_alg === "SHA-256" && typeof reference.digest === "string")
          targets.push(reference.digest);
    }
    return targets;
  }
  async function completeness(bundle, records) {
    if (!object2(bundle.completeness_certificate) || !object2(bundle.checkpoint)) {
      const absent = {
        status: "withheld",
        findings: ["completeness_evidence_absent"]
      };
      return [absent, absent];
    }
    const certificate = bundle.completeness_certificate, parsed = parseCertificate(certificate, bundle.checkpoint);
    if (!parsed)
      return [
        fail("completeness_certificate_invalid"),
        fail("completeness_certificate_invalid")
      ];
    if (!await rangeValid(parsed.root, parsed.firstSeq, parsed.lastSeq, certificate, parsed.rangeProof))
      return [fail("range_proof_invalid"), fail("range_proof_invalid")];
    const findings = await memberships(parsed.root, parsed.logId, parsed.firstSeq, parsed.lastSeq, certificate.memberships, records);
    return [pass(), findings.length ? fail(...findings) : pass()];
  }
  function parseCertificate(certificate, checkpoint) {
    const { log_id: logId, range_root: rootHex, first_seq: firstSeq, last_seq: lastSeq } = certificate;
    if (typeof logId !== "string" || !isHex64(rootHex) || !integer(firstSeq) || !integer(lastSeq) || firstSeq < 1 || lastSeq < firstSeq || checkpoint.root !== rootHex)
      return;
    const range = object2(certificate.range_proof) ? certificate.range_proof : undefined, fromSeq = range?.from_seq, toSeq = range?.to_seq, size = range?.size, from = parseProof(range?.inclusion_from), to = parseProof(range?.inclusion_to);
    if (!integer(fromSeq) || !integer(toSeq) || !integer(size) || !from || !to || checkpoint.mmr_size !== size)
      return;
    return {
      root: hex2(rootHex),
      logId,
      firstSeq,
      lastSeq,
      rangeProof: { fromSeq, toSeq, size, from, to }
    };
  }
  async function rangeValid(root, first, last, certificate, proof) {
    return typeof certificate.first_digest === "string" && typeof certificate.last_digest === "string" && proof.fromSeq === first && proof.toSeq === last && proof.from.leaf_index === first - 1 && proof.to.leaf_index === last - 1 && await verifyProof(root, certificate.first_digest, proof.from) && await verifyProof(root, certificate.last_digest, proof.to);
  }
  async function memberships(root, logId, first, last, raw, records) {
    if (!object2(raw))
      return ["memberships_absent"];
    const bySequence = new Set, findings = [];
    for (const [id, member] of Object.entries(raw)) {
      if (!isHex64(id) || !records.has(id) || !object2(member)) {
        findings.push(`membership_record_unknown:${id}`);
        continue;
      }
      const coordinates = object2(member.log_coordinates) ? member.log_coordinates : undefined;
      if (!coordinates) {
        findings.push(`membership_coordinates_missing:${id}`);
        continue;
      }
      const { seq, leaf_index: leaf } = coordinates;
      if (coordinates.log_id !== logId || !integer(seq) || !integer(leaf) || seq < first || seq > last || leaf !== seq - 1) {
        findings.push(`membership_coordinates_invalid:${id}`);
        continue;
      }
      if (bySequence.has(seq)) {
        findings.push(`membership_seq_duplicate:${seq}`);
        continue;
      }
      bySequence.add(seq);
      const proof = parseProof(member.inclusion_proof);
      if (!proof || !await verifyProof(root, id, proof))
        findings.push(`membership_proof_invalid:${id}`);
    }
    for (let seq = first;seq <= last; seq += 1)
      if (!bySequence.has(seq))
        findings.push(`membership_record_missing:${seq}`);
    return findings;
  }
  function parseProof(raw) {
    if (!object2(raw) || raw.v !== 1 || raw.kind !== "inclusion" || !integer(raw.size) || !integer(raw.leaf_index) || raw.size < 0 || raw.leaf_index < 0)
      return;
    const hashes = (value) => Array.isArray(value) && value.every(isHex64) ? value : undefined;
    const witness = hashes(raw.witness), left = hashes(raw.peaks_left), right = hashes(raw.peaks_right);
    return witness && left && right ? {
      v: 1,
      kind: "inclusion",
      size: raw.size,
      leaf_index: raw.leaf_index,
      witness,
      peaks_left: left,
      peaks_right: right
    } : undefined;
  }
  async function verifyProof(root, identity, proof) {
    const flattened = proof.witness.map(hex2);
    if (proof.peaks_right.length)
      flattened.push(await rootFromPeaks2(proof.peaks_right.map(hex2)));
    flattened.push(...proof.peaks_left.map(hex2).toReversed());
    return verifyHexInclusion2(root, BigInt(proof.size), BigInt(proof.leaf_index), identity, flattened);
  }
  async function disclosures(raw, records) {
    if (raw === undefined)
      raw = {};
    if (!object2(raw))
      return [{ capsuleId: "", member: "", status: DISCLOSURE_MISMATCH }];
    const findings = [];
    for (const [id, record] of [...records.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      const supplied = object2(raw[id]) ? raw[id] : {};
      for (const [member, path] of Object.entries(disclosureEligibleFields))
        if (!(member in supplied) && typeof resolveDisclosurePath(record, path) === "string")
          findings.push({ capsuleId: id, member, status: "withheld" });
    }
    for (const id of Object.keys(raw).sort()) {
      const members = raw[id], record = records.get(id);
      if (!object2(members) || !record) {
        findings.push({ capsuleId: id, member: "", status: DISCLOSURE_MISMATCH });
        continue;
      }
      for (const member of Object.keys(members).sort()) {
        const path = disclosureEligibleFields[member];
        if (!path) {
          findings.push({
            capsuleId: id,
            member,
            status: DISCLOSURE_INELIGIBLE_FIELD
          });
          continue;
        }
        const committed = resolveDisclosurePath(record, path);
        if (!isHex64(committed)) {
          findings.push({
            capsuleId: id,
            member,
            status: DISCLOSURE_NO_COMMITTED_DIGEST
          });
          continue;
        }
        let status = DISCLOSURE_MISMATCH;
        try {
          if (await jsonDigest(members[member]) === committed)
            status = DISCLOSURE_MATCH;
        } catch {}
        findings.push({ capsuleId: id, member, status });
      }
    }
    return findings;
  }
  function extensions(raw) {
    return object2(raw) ? Object.keys(raw).sort().map((kind) => ({
      kind,
      status: "uninterpreted",
      integrityCovered: true
    })) : [];
  }

  // src/aac-crypto.js
  var text2 = new TextDecoder("utf-8", { fatal: true });
  globalThis.AacCrypto = Object.freeze({
    computeCapsuleId,
    verifyClass1,
    verifyDisclosureEnvelope,
    verifyBundle,
    encodeFragment,
    decodeFragment,
    jsonDigest,
    canonicalPayloadText(value) {
      return text2.decode(jcs(value));
    }
  });
})();
