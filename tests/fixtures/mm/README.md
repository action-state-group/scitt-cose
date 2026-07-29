# MachineMandate test fixtures

Byte-verbatim copies from tyche-institute/machine-mandate@524e6a3129b7f1ab850dd9471967458d3cb6f4cd

| File | Raw SHA-256 | Canonical-JSON SHA-256 |
|------|-------------|------------------------|
| demo.aep.json | 2ed1661abb839010b23617b19ee01c5a3549e2d2ca71a4fd37c01f0c2080155d | 63bc7577d7929da79db0d6b045dd1cbdd2e9fb0a708618e3a5093869b8c2bdce |
| ear-A_good_fresh.json | eaf3d03efd9f8896e8ffb4087c1f9ba384229afb0fc09e41ee2afcfb67100cfa | 8cd9e0588b83416891ff1c4480767daeeaa2d82324dc01bda4114f6c2e98c2b3 |
| ear-B_outcome_swapped.json | 030ec18513962ae2ebbd02ac657266484abbbc070244fc178528f78ea041f650 | 4ac69f7b8524a7084be503196d3b0a3aaedac99b42422ae6fe5be198ffb3b2a2 |
| run-credential-mint-record.json | 82e93433582a2992524499d66b10eec7a9e340a69e5cd91c73cfb3a5fd450935 | be779f307e5357ccce504dd0bf920ec1f39b8f4652726eb912ee99e30c195de1 |

Canonical-JSON = json.dumps(parsed, sort_keys=True, separators=(",",":"), ensure_ascii=True) → sha256
Detection uses canonical-JSON digest (AEP/EAR) or credential_claims.vct discriminator (mint record).
