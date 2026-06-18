# Drill Report: Keybox Metadata & Encryption Architecture Refactoring

Date: 2026-06-16
Gate: **Go**

---

## 1. Problem Restatement

The user identified four interconnected problem categories when attempting to add credential descriptions for LLM-based auto-selection in Keybox-CLI:

### A. Feature Gap: No Metadata
Credential storage uses only filesystem paths (`<domain>/<account>.enc`) and contains zero metadata — no descriptions, tags, timestamps, or labels. This makes LLM-based credential selection impossible and blocks future features (expiry tracking, usage statistics, tag-based filtering).

### B. Security Architecture Review
The current two-layer encryption architecture (ROT → decrypt age X25519 identity → encrypt/decrypt credentials) was questioned: why not use ROT directly? After review, the user accepted the two-layer design as industry-standard (supported by age's own design, sops, Bitwarden, 1Password, and Vault), with multiple justifications beyond "ROT doesn't stay in memory": multi-recipient support, key rotation, streaming AEAD, and in-memory separation.

### C. Storage Format Concerns
File-per-secret storage (`store/<domain>/<account>.enc`) has inherent integrity problems: each file is independently authenticated, but there is no cross-file integrity. Any metadata stored separately would be even more vulnerable to loss or desynchronization. A single-file packaging approach would naturally solve this.

### D. External Research Need
Before committing to a design, the user wanted to understand how established open-source tools handle ROT design, encrypted data + metadata packaging, and integrity protection.

### Drill Questions Asked

1. **What is the LLM usage scenario?** → Answer: B + C — LLM reads credential list to select the right one; metadata confidentiality is lower than credentials but needs integrity.
2. **After learning two-layer hierarchy is industry-standard, accept or still question?** → Answer: Accepted. Focus on metadata + integrity.
3. **Metadata security level for LLM search?** → Answer: (A) cleartext + MAC, or (B) encrypted + separate decrypt layer. The answer depends on storage format choice.
4. **Credential count and change frequency?** → Answer: <100 credentials, read-heavy, low change frequency. Single-file full read/write overhead is negligible.

---

## 2. Context & Current State

| Dimension | Current State |
|-----------|---------------|
| **Language** | Rust |
| **Encryption** | age (X25519 key exchange + ChaCha20-Poly1305 AEAD) |
| **Key hierarchy** | 2-tier: ROT → decrypt X25519 identity → encrypt/decrypt credentials |
| **ROT tiers** | Secret (Keychain/DPAPI/machine-id), Confidential (passphrase), Top-Secret (key file) |
| **Credential storage** | Per-file `store/<domain>/<account>.enc`, age binary format |
| **Metadata** | None — only filesystem path encodes domain/account |
| **Integrity (per credential)** | age's built-in: HMAC-SHA256 on header + ChaCha20-Poly1305 per-chunk AEAD |
| **Integrity (cross-credential)** | None — file-separated storage means no global integrity |
| **LLM support** | None — no queryable credential list or descriptions |
| **Affected users** | Single-user CLI tool; all users would benefit from metadata |
| **Frequency of change** | Credentials: add infrequently, get frequently; architecture: this refactoring |

---

## 3. External Landscape

### A. Bitwarden — "encrypted JSON blob, AES-CBC + independent HMAC"

- **CipherString format**: `<type>.<ciphertext>|<iv>|<hmac>` per encrypted field
- **Integrity**: HMAC-SHA256 over IV || ciphertext per field. No item-level or vault-level MAC — fields can be reordered, added, or removed without cryptographic detection.
- **Metadata**: Partially encrypted — `name`, `username`, `password`, `notes` are encrypted; `type`, `favorite`, `creationDate`, `revisionDate` are cleartext (enables server-side search indexing).
- **Read/write**: Field-level — decrypt/encrypt only the changed field. No full-vault operations.
- **Key insight**: Cleartext structural metadata is a deliberate trade-off for searchability. Per-field integrity without cross-field binding is a known limitation.

### B. 1Password — encrypted SQLite + three-tier key hierarchy

- **Key hierarchy**: Account Password + Secret Key → [2SKD: PBKDF2] → Account Unlock Key → Master Unlock Key → Vault Key → per-item AES-256 key
- **Integrity**: AES-256-GCM (AEAD) per blob. Confidentiality + authenticity in one operation.
- **Metadata**: ALL metadata encrypted — item names, URLs, tags, timestamps are binary blobs in SQLite. Server has zero knowledge.
- **Read/write**: Item-level — each item independently encrypted with its own key.
- **Key insight**: True zero-knowledge metadata. The per-item key approach enables granular encryption but requires a complex key wrapping hierarchy.

### C. sops — "structured file, cleartext keys + encrypted values + file-level MAC"

- **Per-value format**: `ENC[AES256_GCM,data:<b64>,iv:<b64>,aad:<key-path>,tag:<b64>]`
- **Two-layer integrity**:
  1. Per-value: AAD = parent key path (e.g., `db_user_`), binding value to position in tree
  2. File-level: HMAC over all leaf values (sorted by key path), then encrypted with data key and stored under `sops.mac`
- **Metadata**: Keys/structures are cleartext; values are encrypted; `sops` metadata block has mixed cleartext/encrypted fields.
- **Read/write**: File-level — entire tree is traversed, modified values re-encrypted, new file MAC computed.
- **Key insight**: The two-layer integrity model (positional binding + global MAC) is the most sophisticated among all tools studied and directly applicable to a single-file credential store.

### D. HashiCorp Vault — barrier encryption

- **Storage entry format**: `[term:4][ver:1][nonce:12][ct+tag]`
- **Integrity**: AES-256-GCM (AEAD) per entry. v2 uses storage path as AAD to cryptographically bind ciphertext to its key, preventing cross-entry substitution.
- **Key hierarchy**: Unseal key → root key → keyring (term keys) → storage entries
- **Read/write**: Entry-level — single entry read/write. Old entries continue using old term keys.
- **Key insight**: Path-binding as AAD (v2 fix) is a clean solution to the "swapping entries" attack that applies equally to single-file structured stores.

### E. gopass/pass — file-per-secret

- **Storage**: One GPG/age encrypted file per secret in a directory tree
- **Integrity**: Per file (GPG MDC or age chunk MAC). File names, directory structure, and `.gpg-id` recipient list have NO cryptographic integrity protection.
- **Metadata**: Filesystem paths = secret names. Git for history. No structured metadata.
- **Known gap**: An attacker with write access can rename, delete, or add files without cryptographic detection.
- **Key insight**: This is exactly the vulnerability the user anticipated — file-separated storage inherently lacks cross-file integrity.

### F. age — file format (currently used by Keybox)

- **Format**: `age-encryption.org/v1` header → recipient stanzas → header HMAC → stream nonce → ChaCha20-Poly1305 chunks
- **Header integrity**: HMAC-SHA256(fileKey, header) — prevents stanza tampering
- **Body integrity**: Per-64KB-chunk Poly1305 tags; chunk counter in nonce prevents reordering; last-chunk flag prevents truncation
- **Key insight**: age already provides robust single-file integrity. The missing piece for Keybox is structured integrity *within* the decrypted payload.

### Comparison Summary

| Project | Integrity Scope | Metadata Encrypted? | Read/Write Scope |
|---------|----------------|---------------------|------------------|
| Bitwarden | Per field (no cross-field binding) | Partial | Field-level |
| 1Password | Per blob (AEAD) | All | Item-level |
| sops | Per value (AAD-bound) + file MAC | Keys cleartext, values encrypted | File-level |
| Vault v2 | Per entry (path-bound AAD) | All values, paths cleartext | Entry-level |
| gopass/pass | Per file (no cross-file) | File names cleartext | File-level |
| age | Per file (header HMAC + body AEAD) | N/A | File-level (streaming) |

---

## 4. Gap & Value Analysis

### Gap: Is It Real?

| Gap | Severity | Is there an existing solution? |
|-----|----------|-------------------------------|
| No metadata (descriptions, tags, timestamps) | High — blocks LLM integration and advanced features | No. Keybox's own codebase has zero metadata support. |
| No cross-credential integrity | Medium — current design has no way to detect tampering across credentials | No. age gives per-file integrity only. |
| File-separated storage fragility | Medium — risk of partial data loss | No. Current format is inherently file-separated. |

### Can Existing Tools Cover These Needs?

No single existing tool covers all three gaps in a way that fits Keybox's use case:

- **Bitwarden/1Password**: Full password managers with cloud sync — overkill and not suitable as a local CLI building block.
- **sops**: Closest match conceptually (structured file + two-layer integrity), but designed for config files (keys cleartext by design) and uses KMS/PGP, not age-native.
- **gopass/pass**: File-per-secret model has the exact integrity gap the user identified.
- **age**: Provides the encryption primitive but has no concept of structured payloads or metadata.

### Is the Gap Worth Filling?

**Yes.** The user's scenario (<100 credentials, read-heavy, low mutation) makes a single-file encrypted store both practical and elegant. The technical complexity is well-understood (age provides encryption, sops provides the integrity pattern), and the scope is well-bounded (payload format redesign, no changes to ROT or key hierarchy).

---

## 5. Balanced Assessment

### Strengths (Why This Is Worth Doing)

1. **Clear, validated user need**: LLM-based credential selection is a real workflow improvement, not a hypothetical feature.
2. **Well-bounded scope**: No changes to the key hierarchy, ROT design, or age encryption layer. Design is focused on the payload format inside age's encrypted body.
3. **Strong prior art**: sops' two-layer integrity model (positional binding + file MAC) and Vault v2's path-binding AAD are proven patterns that map directly to a single-file store.
4. **Low risk of over-engineering**: <100 records, read-heavy — the simplest correct design will also be the most performant. No premature optimization needed.
5. **Age-native**: age's ChaCha20-Poly1305 AEAD + HMAC header already provides the outer integrity layer. The inner integrity layer is additive, not a replacement.
6. **Natural migration path**: A migration tool can read the old file-per-secret format and produce the new single-file format atomically.

### Weaknesses & Risks (Why It Might Fail or Be Unnecessary)

1. **Single-file corruption risk**: A bug in the serialization/encryption loop could corrupt the entire credential store. Mitigation: atomic write (write to temp file + rename) and optional automatic backup before writes.
2. **Breaking format change**: Existing `store/<domain>/<account>.enc` files are incompatible with the new format. Requires a migration tool and clear user communication.
3. **Git-diff unfriendly**: A single encrypted binary blob is not diffable. For users who currently use git to version their credential store (not recommended but possible), this is a regression.
4. **Memory footprint**: The entire decrypted store lives in memory. At <100 credentials (maybe a few KB each), this is negligible now, but could become a concern if credential counts grow 10x+.
5. **Concurrency**: A single file with in-place modification becomes a concurrency bottleneck if the daemon and CLI both need write access. Mitigation: since mutation is rare, a simple file lock suffices.
6. **Metadata encryption vs. LLM accessibility tension**: If metadata is fully encrypted, LLM search requires a full unlock first — this could be slow or require the daemon to always hold decrypted state. If metadata is cleartext (sops-style), LLM can search without unlocking but service names are exposed.

---

## 6. Recommendation

**Gate: Go**

The requirement is real and well-scoped. The key architecture decision (keep two-layer hierarchy, move to single-file storage) is supported by extensive industry prior art. The design space is well-understood:
- **Layer 1 (unchanged)**: Age encryption with existing ROT → identity key hierarchy
- **Layer 2 (new)**: Structured payload format inside age's encrypted body, supporting:
  - Multiple credentials in a single age-encrypted file
  - Rich metadata per credential (description, tags, timestamps, LLM hints)
  - Two-layer integrity: positional binding (like sops AAD) + store-level MAC
  - Optional: metadata sub-key for LLM-searchable partial decryption

**Next step**: Transition to brainstorming phase to design the specific payload format and integrity scheme.
