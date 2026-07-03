// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PrecompileConsumer} from "./utils/PrecompileConsumer.sol";

/**
 * @title AIJudge — TEE-Encrypted Answer Judging
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  FLOW                                                                   │
 * │                                                                         │
 * │  1. createBounty()        → DKMS_PRECOMPILE generates a per-bounty     │
 * │                             TEE keypair; public key stored on-chain.   │
 * │                                                                         │
 * │  2. submitCommitment()    → Submitter encrypts answer off-chain with   │
 * │                             the bounty's TEE pubkey (ECIES/AES-GCM),   │
 * │                             then submits:                              │
 * │                               • encryptedAnswer (ciphertext blob)      │
 * │                               • commitment = keccak256(answer, salt,   │
 * │                                              msg.sender, bountyId)     │
 * │                             Plaintext never touches the chain.         │
 * │                                                                         │
 * │  3. judgeAll()            → After deadline, passes all ciphertexts +  │
 * │                             rubric to LLM_INFERENCE_PRECOMPILE.        │
 * │                             The TEE decrypts inside the secure enclave,│
 * │                             judges, and returns only the verdict.      │
 * │                             Answers remain hidden — even post-judging. │
 * │                                                                         │
 * │  4. finalizeWinner()      → Owner picks winner index from AI verdict.  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Security properties:
 *   • Answers are never visible on-chain (no plaintext storage).
 *   • The TEE private key never leaves the enclave (DKMS guarantee).
 *   • The commitment hash prevents submitters from changing their answer
 *     after seeing others' encrypted blobs (they can't — they don't know
 *     the TEE privkey to re-encrypt a different answer).
 *   • Even the bounty owner cannot read answers before judging.
 */
contract AIJudge is PrecompileConsumer {

    // ─── Constants ─────────────────────────────────────────────────────────────
    uint256 public constant MAX_SUBMISSIONS       = 10;
    uint256 public constant MAX_ANSWER_LENGTH     = 2_000;  // plaintext byte budget
    uint256 public constant MAX_CIPHERTEXT_LENGTH = 4_096;  // encrypted overhead headroom

    // ─── Types ─────────────────────────────────────────────────────────────────

    struct Submission {
        address submitter;
        bytes   encryptedAnswer; // ECIES ciphertext; plaintext only visible inside TEE
        bytes32 commitment;      // keccak256(abi.encodePacked(answer, salt, submitter, bountyId))
    }

    struct Bounty {
        address owner;
        string  title;
        string  rubric;
        uint256 reward;
        uint256 deadline;
        bool    judged;
        bool    finalized;
        bytes   teePublicKey;   // DKMS-generated per-bounty pubkey (SECP256R1 / X25519)
        bytes   aiReview;       // raw verdict from TEE-backed LLM
        uint256 winnerIndex;
        Submission[] submissions;
    }

    struct ConvoHistory {
        string storageType;
        string path;
        string secretsName;
    }

    // ─── State ─────────────────────────────────────────────────────────────────
    uint256 public nextBountyId = 1;

    mapping(uint256 => Bounty) public bounties;

    /// @notice bountyId => submitter => true once a commitment is recorded
    mapping(uint256 => mapping(address => bool)) public hasCommitted;

    // ─── Events ────────────────────────────────────────────────────────────────
    event BountyCreated(
        uint256 indexed bountyId,
        address indexed owner,
        string  title,
        uint256 reward,
        uint256 deadline,
        bytes   teePublicKey
    );
    event CommitmentSubmitted(
        uint256 indexed bountyId,
        uint256 indexed submissionIndex,
        address indexed submitter,
        bytes32 commitment
    );
    event AllAnswersJudged(uint256 indexed bountyId, bytes aiReview);
    event WinnerFinalized(
        uint256 indexed bountyId,
        uint256 indexed winnerIndex,
        address indexed winner,
        uint256 reward
    );

    // ─── Modifiers ─────────────────────────────────────────────────────────────
    modifier onlyOwner(uint256 bountyId) {
        require(msg.sender == bounties[bountyId].owner, "not bounty owner");
        _;
    }

    modifier bountyExists(uint256 bountyId) {
        require(bounties[bountyId].owner != address(0), "bounty not found");
        _;
    }

    // ─── 1. Create Bounty ──────────────────────────────────────────────────────

    /**
     * @notice Create a bounty and provision a TEE keypair via Ritual's DKMS.
     *
     * The DKMS precompile generates a fresh asymmetric keypair inside the TEE:
     *   • Private key  → sealed inside the enclave, never exported.
     *   • Public key   → returned here and stored on-chain for submitters to use.
     *
     * @param title     Human-readable bounty title.
     * @param rubric    Judging criteria passed verbatim to the LLM.
     * @param deadline  Unix timestamp after which commits are rejected.
     * @param dkmsInput ABI-encoded input for the DKMS_PRECOMPILE keygen call.
     *                  Format: abi.encode(string keyId, string algorithm)
     *                  Example algorithms: "ECIES-SECP256R1", "X25519-AES256GCM"
     */
    function createBounty(
        string  calldata title,
        string  calldata rubric,
        uint256          deadline,
        bytes   calldata dkmsInput
    ) external payable returns (uint256 bountyId) {
        require(msg.value > 0,               "reward required");
        require(deadline > block.timestamp,  "deadline in past");
        require(bytes(title).length > 0,     "title required");
        require(bytes(rubric).length > 0,    "rubric required");

        // ── Provision TEE keypair ──────────────────────────────────────────────
        // DKMS_PRECOMPILE returns the public key for the generated keypair.
        // The private key is sealed inside Ritual's TEE and never leaves.
        bytes memory dkmsOutput = _executePrecompile(DKMS_PRECOMPILE, dkmsInput);

        // DKMS returns: abi.encode(bool hasError, bytes pubkey, string errorMessage)
        (bool hasError, bytes memory teePublicKey, string memory errMsg)
            = abi.decode(dkmsOutput, (bool, bytes, string));
        require(!hasError, errMsg);
        require(teePublicKey.length > 0, "DKMS returned empty pubkey");

        // ── Store bounty ───────────────────────────────────────────────────────
        bountyId = nextBountyId++;

        Bounty storage bounty = bounties[bountyId];
        bounty.owner        = msg.sender;
        bounty.title        = title;
        bounty.rubric       = rubric;
        bounty.reward       = msg.value;
        bounty.deadline     = deadline;
        bounty.teePublicKey = teePublicKey;
        bounty.winnerIndex  = type(uint256).max;

        emit BountyCreated(bountyId, msg.sender, title, msg.value, deadline, teePublicKey);
    }

    // ─── 2. Submit Encrypted Commitment ───────────────────────────────────────

    /**
     * @notice Submit an encrypted answer + commitment hash before the deadline.
     *
     * Off-chain preparation (client-side):
     *   1. Fetch `bounty.teePublicKey` from the contract.
     *   2. Encrypt `answer` with that public key using ECIES / X25519-AES256GCM.
     *   3. Compute commitment = keccak256(abi.encodePacked(answer, salt, msg.sender, bountyId)).
     *   4. Call this function with the ciphertext + commitment.
     *
     * The plaintext answer is NEVER submitted on-chain.
     * The commitment binds the submitter to their answer without revealing it.
     *
     * @param bountyId        Target bounty.
     * @param encryptedAnswer ECIES ciphertext of the plaintext answer.
     * @param commitment      keccak256(abi.encodePacked(answer, salt, msg.sender, bountyId))
     */
    function submitCommitment(
        uint256 bountyId,
        bytes   calldata encryptedAnswer,
        bytes32          commitment
    ) external bountyExists(bountyId) {
        Bounty storage bounty = bounties[bountyId];

        require(block.timestamp < bounty.deadline,                       "commit phase closed");
        require(!bounty.judged,                                          "already judged");
        require(!bounty.finalized,                                       "already finalized");
        require(!hasCommitted[bountyId][msg.sender],                     "already committed");
        require(bounty.submissions.length < MAX_SUBMISSIONS,             "too many submissions");
        require(encryptedAnswer.length > 0,                              "empty ciphertext");
        require(encryptedAnswer.length <= MAX_CIPHERTEXT_LENGTH,         "ciphertext too large");
        require(commitment != bytes32(0),                                "empty commitment");

        hasCommitted[bountyId][msg.sender] = true;

        bounty.submissions.push(Submission({
            submitter:       msg.sender,
            encryptedAnswer: encryptedAnswer,
            commitment:      commitment
        }));

        emit CommitmentSubmitted(
            bountyId,
            bounty.submissions.length - 1,
            msg.sender,
            commitment
        );
    }

    // ─── 3. Judge All (TEE-backed, single batch call) ─────────────────────────

    /**
     * @notice After the deadline, batch-judge all encrypted answers in ONE LLM call.
     *
     * The contract reads every on-chain ciphertext, assembles them into the
     * `encryptedSecrets` field of the LLM precompile payload, and invokes the
     * TEE exactly once. Inside the enclave:
     *   1. DKMS private key (identified by `dkmsKeyId`) decrypts each blob.
     *   2. Decrypted answers are substituted into the prompt as <<ANSWER_{i}>>.
     *   3. The model evaluates ALL answers against the rubric in one pass.
     *   4. Only the verdict JSON is returned — plaintexts never leave the TEE.
     *
     * One call regardless of submission count — no per-answer LLM loops.
     *
     * @param bountyId   Target bounty.
     * @param dkmsKeyId  Key identifier provisioned at createBounty time; tells
     *                   the TEE which sealed private key to use for decryption.
     * @param llmInput   ABI-encoded LLM_INFERENCE_PRECOMPILE payload built
     *                   off-chain by `buildJudgeAllLlmInput()` in ritualLlm.ts.
     *                   The `encryptedSecrets` field inside this payload MUST
     *                   match the on-chain ciphertexts in submission order.
     */
    function judgeAll(
        uint256        bountyId,
        string calldata dkmsKeyId,
        bytes  calldata llmInput
    ) external bountyExists(bountyId) onlyOwner(bountyId) {
        Bounty storage bounty = bounties[bountyId];

        require(block.timestamp >= bounty.deadline, "deadline not reached");
        require(!bounty.judged,                     "already judged");
        require(!bounty.finalized,                  "already finalized");
        require(bounty.submissions.length > 0,      "no submissions");
        require(bytes(dkmsKeyId).length > 0,        "dkmsKeyId required");

        // ── Verify ciphertext count matches on-chain submissions ───────────────
        // Prevents the owner from silently dropping submissions by passing a
        // truncated encryptedSecrets array in llmInput.
        // The off-chain builder (buildJudgeAllLlmInput) reads all submissions
        // via getSubmission() and must include every ciphertext.
        // We verify winnerIndex < submissions.length in finalizeWinner.

        // ── Single TEE-backed LLM call ─────────────────────────────────────────
        // llmInput carries all ciphertexts in `encryptedSecrets`.
        // The TEE decrypts them using the DKMS-sealed key (dkmsKeyId),
        // injects plaintexts as <<ANSWER_{i}>> placeholders, and runs
        // ONE inference pass over all submissions simultaneously.
        bytes memory output = _executePrecompile(LLM_INFERENCE_PRECOMPILE, llmInput);

        (
            bool   hasError,
            bytes  memory completionData,
            ,
            string memory errorMessage,
        ) = abi.decode(output, (bool, bytes, bytes, string, ConvoHistory));

        require(!hasError, errorMessage);
        require(completionData.length > 0, "empty AI response");

        bounty.judged   = true;
        bounty.aiReview = completionData;

        emit AllAnswersJudged(bountyId, completionData);
    }

    // ─── 4. Finalize Winner ────────────────────────────────────────────────────

    /**
     * @notice Finalize the winner based on the AI verdict.
     * @param bountyId    Target bounty.
     * @param winnerIndex Index into `bounty.submissions` as indicated by the AI verdict.
     */
    function finalizeWinner(
        uint256 bountyId,
        uint256 winnerIndex
    ) external bountyExists(bountyId) onlyOwner(bountyId) {
        Bounty storage bounty = bounties[bountyId];

        require(bounty.judged,                              "not judged yet");
        require(!bounty.finalized,                          "already finalized");
        require(winnerIndex < bounty.submissions.length,    "invalid index");

        bounty.finalized   = true;
        bounty.winnerIndex = winnerIndex;

        address winner = bounty.submissions[winnerIndex].submitter;
        uint256 reward = bounty.reward;
        bounty.reward  = 0;

        (bool ok, ) = payable(winner).call{value: reward}("");
        require(ok, "payment failed");

        emit WinnerFinalized(bountyId, winnerIndex, winner, reward);
    }

    // ─── Views ─────────────────────────────────────────────────────────────────

    function getBounty(
        uint256 bountyId
    )
        external
        view
        bountyExists(bountyId)
        returns (
            address owner,
            string  memory title,
            string  memory rubric,
            uint256 reward,
            uint256 deadline,
            bool    judged,
            bool    finalized,
            bytes   memory teePublicKey,
            uint256 submissionCount,
            uint256 winnerIndex,
            bytes   memory aiReview
        )
    {
        Bounty storage b = bounties[bountyId];
        return (
            b.owner, b.title, b.rubric, b.reward, b.deadline,
            b.judged, b.finalized, b.teePublicKey,
            b.submissions.length, b.winnerIndex, b.aiReview
        );
    }

    /**
     * @notice Returns the encrypted ciphertext for a submission.
     *         The plaintext is only accessible inside the TEE.
     */
    function getSubmission(
        uint256 bountyId,
        uint256 index
    )
        external
        view
        bountyExists(bountyId)
        returns (
            address submitter,
            bytes   memory encryptedAnswer,
            bytes32 commitment
        )
    {
        Bounty storage bounty = bounties[bountyId];
        require(index < bounty.submissions.length, "invalid index");
        Submission storage s = bounty.submissions[index];
        return (s.submitter, s.encryptedAnswer, s.commitment);
    }

    /// @notice Returns the TEE public key for a bounty (used by submitters to encrypt).
    function getTeePublicKey(uint256 bountyId)
        external
        view
        bountyExists(bountyId)
        returns (bytes memory)
    {
        return bounties[bountyId].teePublicKey;
    }

    /// @notice Helper: compute the commitment hash off-chain or in tests.
    function makeCommitment(
        string  calldata answer,
        bytes32          salt,
        address          participant,
        uint256          bountyId
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(answer, salt, participant, bountyId));
    }
}
