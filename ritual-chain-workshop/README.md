# Ritual Chain Workshop — Encrypted Bounty Judge

A trustless bounty system where answers are encrypted with a TEE-generated key,
judged in a single on-chain LLM call, and the plaintext never touches the chain.

---

## Repository layout

```
hardhat/
  contracts/
    AIJudge.sol          — core bounty + commit-reveal + TEE judging logic
    CommitReveal.sol     — standalone commit-reveal helper (any EVM chain)
    utils/
      PrecompileConsumer.sol — Ritual precompile address registry + call wrapper
  ignition/modules/      — deployment modules
web/
  src/
    lib/
      ritualLlm.ts       — builds the encrypted-secrets LLM payload (off-chain)
      aiReview.ts        — decodes the on-chain AI verdict bytes
    abi/                 — contract ABIs for the frontend
    hooks/               — wagmi hooks (useBounty, useWriteTx, …)
    components/          — React UI components
```

---

## Lifecycle

### Phase 0 — Deploy

```
npx hardhat ignition deploy ignition/modules/AIJudge.ts
```

One `AIJudge` contract is deployed. It imports `PrecompileConsumer` which
provides access to Ritual's on-chain precompiles:
- `DKMS_PRECOMPILE` (`0x081B`) — TEE key management
- `LLM_INFERENCE_PRECOMPILE` (`0x0802`) — TEE-backed LLM

---

### Phase 1 — Create Bounty

**Who:** Bounty owner  
**When:** Any time  
**Function:** `createBounty(title, rubric, deadline, dkmsInput)`

```
Owner  ──►  AIJudge.createBounty()
                └─► DKMS_PRECOMPILE
                        ├─ generates per-bounty asymmetric keypair inside TEE
                        ├─ seals private key in enclave (never exported)
                        └─ returns public key
            stores: teePublicKey, rubric, deadline, reward
            emits:  BountyCreated(bountyId, owner, title, reward, deadline, teePublicKey)
```

The `dkmsInput` encodes the key algorithm (e.g. `"X25519-AES256GCM"`) and a
unique `keyId` string that will be used later to retrieve the private key during
judging.

---

### Phase 2 — Submit Commitment  *(before `deadline`)*

**Who:** Any submitter  
**When:** `block.timestamp < bounty.deadline`  
**Function:** `submitCommitment(bountyId, encryptedAnswer, commitment)`

**Off-chain preparation (client):**
```ts
// 1. Fetch the TEE public key
const pubkey = await contract.getTeePublicKey(bountyId);

// 2. Encrypt the answer — plaintext never leaves the client
const encryptedAnswer = eciesEncrypt(pubkey, Buffer.from(answer));

// 3. Compute binding commitment
const salt = crypto.randomBytes(32);
const commitment = keccak256(encodePacked(
  ['string','bytes32','address','uint256'],
  [answer, salt, walletAddress, bountyId]
));

// 4. Submit — no plaintext on-chain
await contract.submitCommitment(bountyId, encryptedAnswer, commitment);
```

**On-chain state written:**
```
submissions[i] = { submitter, encryptedAnswer, commitment }
hasCommitted[bountyId][submitter] = true
```

The commitment hash binds the submitter to their answer without revealing it.
The ciphertext can only be decrypted by the TEE private key.

---

### Phase 3 — Judge All  *(after `deadline`)*

**Who:** Bounty owner  
**When:** `block.timestamp >= bounty.deadline`  
**Function:** `judgeAll(bountyId, dkmsKeyId, llmInput)`

**Off-chain preparation (owner):**
```ts
// Read all ciphertexts from chain
const submissions = await Promise.all(
  Array.from({ length: submissionCount }, (_, i) =>
    contract.getSubmission(bountyId, i)
  )
);

// Build the single batch LLM payload
const llmInput = buildJudgeAllLlmInput({
  executorAddress,
  dkmsKeyId,        // same keyId used at createBounty
  title,
  rubric,
  submissions,      // [ { index, submitter, encryptedAnswer } ]
});

await contract.judgeAll(bountyId, dkmsKeyId, llmInput);
```

**Inside Ritual's TEE (one call, all submissions):**
```
LLM_INFERENCE_PRECOMPILE
  ├─ receives encryptedSecrets[] = all ciphertexts
  ├─ looks up DKMS private key by dkmsKeyId
  ├─ decrypts each blob → plaintext[i]          ← inside enclave only
  ├─ substitutes <<ANSWER_{i}>> in prompt
  ├─ ONE model inference over all answers
  └─ returns { winnerIndex, scores, summary }   ← plaintexts destroyed
```

**On-chain state written:**
```
bounty.judged   = true
bounty.aiReview = completionData   ← verdict JSON only, no answers
```

---

### Phase 4 — Finalize Winner

**Who:** Bounty owner  
**When:** After `judgeAll` succeeds  
**Function:** `finalizeWinner(bountyId, winnerIndex)`

```
Owner reads bounty.aiReview → parses winnerIndex from verdict JSON
Owner calls finalizeWinner(bountyId, winnerIndex)
  ├─ validates: judged, not finalized, index in range
  ├─ sets bounty.finalized = true
  └─ transfers reward ETH to winner
emits: WinnerFinalized(bountyId, winnerIndex, winner, reward)
```

---

## Security properties

| Property | Guarantee |
|---|---|
| Answer hidden before deadline | Ciphertext only on-chain; no plaintext ever submitted |
| Answer hidden after judging | Plaintext only existed inside TEE enclave, then destroyed |
| Owner cannot read answers | TEE private key sealed in DKMS; owner has no access |
| Submitter bound to answer | `keccak256(answer, salt, sender, bountyId)` commitment |
| No per-answer LLM calls | All submissions judged in one TEE inference pass |
| Front-running impossible | Ciphertext is meaningless without the TEE private key |

---

## Running locally

```bash
# Install dependencies
cd hardhat && pnpm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Start frontend
cd ../web && pnpm dev
```

See `hardhat/TEST_PLAN.md` for the full test matrix and `ARCHITECTURE.md` for
the system design rationale.
