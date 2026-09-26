# CLL checkpoint conformance vectors (vendored)

`vectors.json` is a byte-verbatim copy of
`checkpoint-conformance-vectors/vectors.json` from
action-state-group/checkpointed-local-log@0e32989839ddeb13b86af72b5040994b91f0b139

| File | Raw SHA-256 |
|------|-------------|
| vectors.json | e7d2813e8eca011e7d6016ac89ac0f20fb4f74772eb7fa436cc7482290a7a2a2 |

The upstream reference emitter (`cll.checkpoint.emit.CheckpointRecord`)
generated every `digest_hex` and `signature` value from a deterministic
fixture seed (32 bytes of `0x07`, not a real credential). No value in this
file was produced by scitt-cose. `tests/test_checkpoint_verify.py` checks
the raw SHA-256 above before using the file, so an edit here fails the
suite instead of silently re-baselining it.

To refresh, copy the file from a newer upstream commit and update the
commit and digest above in the same change.

Upstream license (BSD 3-Clause), retained as it requires:

    BSD 3-Clause License
    
    Copyright (c) 2026 Action State Group, Inc.
    
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    
    3. Neither the name of the copyright holder nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.
    
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
