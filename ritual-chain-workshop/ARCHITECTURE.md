# Architecture Note — Encrypted Bounty Judge on Ritual

## Problem statement

A standard on-chain bounty has two conflicting requirements:

1. **Anti-front-running** — answers must be hidden until the deadline so late
   entrants cannot copy earlier submissions.
2. **Verifiable judging** — the judging process must be trustless and auditable.

A naive commit-reveal scheme solves (1) but breaks (2): answers become fully
public on-chain at reveal time, and judging is either centralised or requires
expensive on-chain logic. Ritual's TEE infrastructure solves both simultaneously.

---

## Component map

```
┌─────────────────────────────────────────────────────────────────────────┐
│  EVM Chain (Ritual Chain or any EVM)                                    │
│                                                                         │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐  │
│  │  AIJudge.sol │────►│  DKMS_PRECOMPILE  (0x081B)                  │  │
│  │              │     │  • Generates per-bounty keypair in TEE       │  │
│  │              │     │  • Seals privkey — never exported            │  │
│  │              │     │  • Returns pubkey on-chain                   │  │
│  │              │     └─────────────────────────────────────────────┘  │
│  │              │                                                       │
│  │              │     ┌─────────────────────────────────────────────┐  │
│  │              │────►│  LLM_INFERENCE_PRECOMPILE  (0x0802)         │  │
│  │              │     │  • Runs inside Ritual TEE executor           │  │
│  │              │     │  • Decrypts encryptedSecrets[] via DKMS key  │  │
│  │              │     │  • Runs ONE batch LLM inference              │  │
│  │              │     │  • Returns verdict only                      │  │
│  └──────────────┘     └─────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────┐                                                       │
│  │CommitReveal  │  Standalone helper — same commit-reveal primitives    │
│  │   .sol       │  usable independently on any EVM chain               │
│  └──────────────┘                                                       │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Off-chain (browser / script)                                           │
│                                                                         │
│  ritualLlm.ts                                                           │
│  • Reads ciphertexts from chain via getSubmission()                     │
│  • Builds prompt with <<ANSWER_{i}>> placeholders                       │
│  • Packs ciphertexts into encryptedSecrets[]                            │
│  • ABI-encodes full LLM precompile payload                              │
│                                                                         │
│  Client (submitter)                                                     │
│  • Encrypts answer with TEE pubkey (ECIES / X25519-AES256GCM)          │
│  • Computes keccak256(answer, salt, sender, bountyId) commitment        │
│  • Calls submitCommitment() — no plaintext ever sent                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Why DKMS instead of a shared contract key

A single contract-level keypair would mean:
- Every bounty's answers are decryptable by anyone who recovers the key.
- A compromised key exposes all historical submissions retroactively.

Per-bounty DKMS keys scope the blast radius to a single bounty. The private key
is generated fresh for each `createBounty` call, sealed inside the TEE, and
destroyed after judging completes. There is no key material to steal.

---

## Why one LLM call (batch), not N calls

| Approach | LLM calls | Gas | Fairness |
|---|---|---|---|
| Per-answer loop | N | O(N × gas_per_call) | Different model state per call |
| **Batch (this design)** | **1** | **O(1)** | **All answers in same context window** |

Batching is also semantically correct: the model needs to see all answers
simultaneously to rank them against each other. Sequential calls would require
the model to maintain external state across calls, which is not guaranteed.

---

## Commitment vs encryption — why both

| Mechanism | Purpose |
|---|---|
| **Encryption** (ECIES) | Hides the answer from everyone except the TEE |
| **Commitment** (keccak256) | Binds the submitter to their answer before the deadline |

Encryption alone is not enough: a submitter could encrypt a different answer
after seeing others' ciphertexts (since ciphertexts are public on-chain). The
commitment hash, which includes `msg.sender` and `bountyId`, prevents this —
the submitter cannot change their answer without invalidating the commitment.

The TEE could optionally verify the commitment during decryption (decrypt →
recompute hash → compare against on-chain `submission.commitment`) for an
additional integrity check, but this is not required for the current security
model since the submitter cannot know the TEE private key.

---

## Trust model

| Actor | What they can see | What they cannot see |
|---|---|---|
| Submitter | Their own plaintext; all ciphertexts on-chain | Other submitters' answers |
| Bounty owner | All ciphertexts; verdict JSON | Any plaintext answer (ever) |
| Public / chain | All ciphertexts; commitments; verdict | Any plaintext answer |
| Ritual TEE | All plaintexts (during judging only) | Nothing after call returns |
| DKMS enclave | Private key | — (it generates and seals it) |

The only trusted component is Ritual's TEE hardware. If the TEE is compromised,
plaintexts are exposed during the judging window. This is the standard TEE
threat model — the same as any HSM or secure enclave system.

---

## EVM portability

`CommitReveal.sol` has zero Ritual-specific dependencies and works on any EVM
chain. `AIJudge.sol` requires Ritual Chain for the precompile calls
(`DKMS_PRECOMPILE`, `LLM_INFERENCE_PRECOMPILE`). The precompile addresses are
constants in `PrecompileConsumer.sol` and can be overridden for other networks
that implement compatible interfaces.

---

## Data flow summary

```
createBounty        DKMS_PRECOMPILE ──► teePublicKey (on-chain)
                                    └── privkey (sealed in TEE)

submitCommitment    client encrypts answer ──► encryptedAnswer (on-chain)
                    client hashes answer   ──► commitment (on-chain)

judgeAll            encryptedAnswer[0..N] ──► LLM_INFERENCE_PRECOMPILE
                                               │  TEE decrypts via DKMS key
                                               │  ONE LLM inference
                                               └► verdict JSON (on-chain)
                                                  plaintexts destroyed

finalizeWinner      verdict.winnerIndex ──► ETH transfer to winner
```
