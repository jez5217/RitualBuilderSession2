# Test Plan — AIJudge Commit-Reveal & TEE Judging

All tests target `AIJudge.sol`. Mock the Ritual precompiles with stub contracts
that return canned responses so the full flow runs in a local Hardhat network.

---

## Test environment setup

```ts
// Stub DKMS — returns a fixed fake pubkey
// Stub LLM  — returns a fixed verdict JSON
// Deploy AIJudge pointing at stub addresses (or use vm.etch in Foundry)
```

---

## 1. `createBounty`

| # | Scenario | Expected |
|---|---|---|
| 1.1 | Valid call with `msg.value > 0` and future deadline | Bounty created; `teePublicKey` stored; `BountyCreated` emitted |
| 1.2 | `msg.value == 0` | Revert `"reward required"` |
| 1.3 | `deadline <= block.timestamp` | Revert `"deadline in past"` |
| 1.4 | Empty `title` | Revert `"title required"` |
| 1.5 | Empty `rubric` | Revert `"rubric required"` |
| 1.6 | DKMS stub returns `hasError = true` | Revert with DKMS error message |
| 1.7 | DKMS stub returns empty pubkey | Revert `"DKMS returned empty pubkey"` |
| 1.8 | `nextBountyId` increments correctly across two creates | `bountyId` 1 then 2 |

---

## 2. `submitCommitment`

| # | Scenario | Expected |
|---|---|---|
| 2.1 | Valid submission before deadline | Entry stored; `CommitmentSubmitted` emitted |
| 2.2 | Submit at exactly `deadline` (`block.timestamp == deadline`) | Revert `"commit phase closed"` |
| 2.3 | Submit after deadline | Revert `"commit phase closed"` |
| 2.4 | Same submitter commits twice | Revert `"already committed"` |
| 2.5 | `MAX_SUBMISSIONS` (10) already reached | Revert `"too many submissions"` |
| 2.6 | Empty `encryptedAnswer` (`bytes("")`) | Revert `"empty ciphertext"` |
| 2.7 | `encryptedAnswer.length > MAX_CIPHERTEXT_LENGTH` | Revert `"ciphertext too large"` |
| 2.8 | `commitment == bytes32(0)` | Revert `"empty commitment"` |
| 2.9 | Submit to non-existent bountyId | Revert `"bounty not found"` |
| 2.10 | Submit after `judgeAll` has run | Revert `"already judged"` |
| 2.11 | Submit after `finalizeWinner` | Revert `"already finalized"` |
| 2.12 | `hasCommitted` mapping set to `true` after success | Confirmed via direct mapping read |

---

## 3. `judgeAll` — core reveal cases

These are the critical cases. The "reveal" in this TEE model is the moment the
TEE decrypts ciphertexts inside the enclave. The contract-level guards below
ensure only valid, timely, unmanipulated submissions reach the LLM.

| # | Scenario | Expected |
|---|---|---|
| 3.1 | Valid call after deadline with ≥1 submission | `judged = true`; `aiReview` set; `AllAnswersJudged` emitted |
| 3.2 | Call before deadline (`block.timestamp < deadline`) | Revert `"deadline not reached"` |
| 3.3 | Call at exactly `deadline` | Succeeds (boundary: `>=`) |
| 3.4 | Call by non-owner | Revert `"not bounty owner"` |
| 3.5 | Call with zero submissions | Revert `"no submissions"` |
| 3.6 | Call after already judged | Revert `"already judged"` |
| 3.7 | Call after finalized | Revert `"already finalized"` |
| 3.8 | Empty `dkmsKeyId` string | Revert `"dkmsKeyId required"` |
| 3.9 | LLM stub returns `hasError = true` | Revert with LLM error message |
| 3.10 | LLM stub returns empty `completionData` | Revert `"empty AI response"` |
| 3.11 | `llmInput` carries fewer ciphertexts than `submissions.length` | Off-chain builder must include all; test that `buildJudgeAllLlmInput` includes every `encryptedAnswer` from `getSubmission` |
| 3.12 | Single submission — LLM returns `winnerIndex: 0` | Accepted; `aiReview` stored |
| 3.13 | Max submissions (10) — all ciphertexts forwarded | Single LLM call succeeds; no per-answer loops |

### Reveal integrity cases

| # | Scenario | Expected |
|---|---|---|
| 3.R1 | Submitter A committed but submitter B did not — only A's ciphertext in submissions[] | Only A eligible; B has no entry |
| 3.R2 | Submitter replaces their ciphertext by calling `submitCommitment` again | Revert `"already committed"` — original ciphertext immutable |
| 3.R3 | Owner passes a tampered ciphertext in `llmInput.encryptedSecrets` instead of the on-chain one | TEE decryption fails (MAC mismatch); LLM returns error; contract reverts |
| 3.R4 | Commitment hash does not match `keccak256(answer, salt, submitter, bountyId)` | Commitment is stored but mismatch is detectable post-judging via off-chain verification against `submission.commitment` |
| 3.R5 | Two submitters with identical ciphertexts (replay) | Both entries stored (different submitter addresses); commitment hashes differ because `msg.sender` is bound |

---

## 4. `finalizeWinner`

| # | Scenario | Expected |
|---|---|---|
| 4.1 | Valid call after `judgeAll` | Reward transferred; `WinnerFinalized` emitted; `finalized = true` |
| 4.2 | Call before `judgeAll` | Revert `"not judged yet"` |
| 4.3 | Call twice | Revert `"already finalized"` |
| 4.4 | `winnerIndex >= submissions.length` | Revert `"invalid index"` |
| 4.5 | Call by non-owner | Revert `"not bounty owner"` |
| 4.6 | Winner address is a contract that reverts on ETH receive | Revert `"payment failed"` |
| 4.7 | `bounty.reward` zeroed after payout | Confirmed via `getBounty` |
| 4.8 | `winnerIndex == type(uint256).max` (unset sentinel) | Revert `"invalid index"` (out of range) |

---

## 5. View functions

| # | Scenario | Expected |
|---|---|---|
| 5.1 | `getBounty` on non-existent id | Revert `"bounty not found"` |
| 5.2 | `getSubmission` out-of-range index | Revert `"invalid index"` |
| 5.3 | `getTeePublicKey` returns stored pubkey | Matches value from `BountyCreated` event |
| 5.4 | `makeCommitment` pure — matches client-side keccak | `keccak256(answer, salt, addr, bountyId)` |

---

## 6. End-to-end flow

| # | Scenario | Expected |
|---|---|---|
| 6.1 | Full happy path: create → 3 commits → judgeAll → finalizeWinner | Winner receives full `msg.value`; all state flags set correctly |
| 6.2 | Two bounties in parallel — independent state | No cross-contamination of submissions, keys, or verdicts |
| 6.3 | Bounty with 1 submission skips to finalize | Works; winner is index 0 |

---

## Mock precompile setup (Hardhat)

```ts
// In test setup — etch stub bytecode at precompile addresses
const dkmsStub = await deployDkmsStub(fakePubkey);
const llmStub  = await deployLlmStub({ winnerIndex: 1, scores: [60, 95], summary: "ok" });

await network.provider.send("hardhat_setCode", [
  "0x000000000000000000000000000000000000081B", // DKMS
  await dkmsStub.getDeployedCode(),
]);
await network.provider.send("hardhat_setCode", [
  "0x0000000000000000000000000000000000000802", // LLM
  await llmStub.getDeployedCode(),
]);
```
