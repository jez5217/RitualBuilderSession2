// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CommitReveal
 * @notice Commit-reveal scheme scoped per bounty, compatible with AIJudge.
 *
 * Commitment formula:
 *   keccak256(abi.encodePacked(answer, salt, msg.sender, bountyId))
 *
 * Flow:
 *   1. commit(bountyId, hash)        — before bounty deadline
 *   2. reveal(bountyId, answer, salt) — after deadline, within reveal window
 *   3. AIJudge.judgeAll only considers entries where revealed == true
 */
contract CommitReveal {
    // ─── Errors ────────────────────────────────────────────────────────────────
    error AlreadyCommitted();
    error NothingCommitted();
    error AlreadyRevealed();
    error CommitPhaseClosed();
    error RevealPhaseNotOpen();
    error RevealPhaseClosed();
    error HashMismatch();
    error InvalidDeadline();
    error AnswerTooLong();
    error BountyNotRegistered();
    error BountyAlreadyRegistered();
    error NotRevealedYet();

    // ─── Constants ─────────────────────────────────────────────────────────────
    /// @notice Maximum answer length (mirrors AIJudge.MAX_ANSWER_LENGTH).
    uint256 public constant MAX_ANSWER_LENGTH = 2_000;

    /// @notice How long after the commit deadline the reveal window stays open.
    uint256 public constant REVEAL_WINDOW = 1 hours;

    // ─── Types ─────────────────────────────────────────────────────────────────
    struct Entry {
        bytes32 commitment; // keccak256(answer, salt, submitter, bountyId)
        string  answer;     // plaintext answer (set on reveal)
        bytes32 salt;       // random salt      (set on reveal)
        bool    revealed;
    }

    struct BountyMeta {
        uint256 deadline;   // submission (commit) deadline — mirrors AIJudge.Bounty.deadline
        bool    registered;
    }

    // ─── State ─────────────────────────────────────────────────────────────────
    /// @notice bountyId => BountyMeta
    mapping(uint256 => BountyMeta) public bountyMeta;

    /// @notice bountyId => submitter => Entry
    mapping(uint256 => mapping(address => Entry)) public entries;

    // ─── Events ────────────────────────────────────────────────────────────────
    event BountyRegistered(uint256 indexed bountyId, uint256 deadline);
    event Committed(uint256 indexed bountyId, address indexed participant, bytes32 commitment);
    event Revealed(uint256 indexed bountyId, address indexed participant, string answer, bytes32 salt);

    // ─── Bounty Registration ───────────────────────────────────────────────────

    /**
     * @notice Register a bounty's deadline so this contract can enforce phases.
     *         Called by the bounty owner (or AIJudge itself) after createBounty.
     * @param bountyId  The bounty identifier from AIJudge.
     * @param deadline  block.timestamp deadline copied from AIJudge.Bounty.deadline.
     */
    function registerBounty(uint256 bountyId, uint256 deadline) external {
        if (bountyMeta[bountyId].registered) revert BountyAlreadyRegistered();
        if (deadline <= block.timestamp)     revert InvalidDeadline();

        bountyMeta[bountyId] = BountyMeta({deadline: deadline, registered: true});
        emit BountyRegistered(bountyId, deadline);
    }

    // ─── Commit ────────────────────────────────────────────────────────────────

    /**
     * @notice Submit a commitment for a specific bounty.
     * @param bountyId    Target bounty.
     * @param commitment  keccak256(abi.encodePacked(answer, salt, msg.sender, bountyId))
     */
    function submitCommitment(uint256 bountyId, bytes32 commitment) external {
        BountyMeta storage meta = bountyMeta[bountyId];
        if (!meta.registered)                               revert BountyNotRegistered();
        if (block.timestamp >= meta.deadline)               revert CommitPhaseClosed();
        if (entries[bountyId][msg.sender].commitment != 0)  revert AlreadyCommitted();

        entries[bountyId][msg.sender].commitment = commitment;
        emit Committed(bountyId, msg.sender, commitment);
    }

    // ─── Reveal ────────────────────────────────────────────────────────────────

    /**
     * @notice Reveal the answer after the submission deadline.
     * @param bountyId  Target bounty.
     * @param answer    Plaintext answer string committed earlier.
     * @param salt      Random salt used when building the commitment.
     *
     * Valid window: (deadline, deadline + REVEAL_WINDOW]
     */
    function revealAnswer(uint256 bountyId, string calldata answer, bytes32 salt) external {
        BountyMeta storage meta = bountyMeta[bountyId];
        if (!meta.registered)                                  revert BountyNotRegistered();
        if (block.timestamp <= meta.deadline)                  revert RevealPhaseNotOpen();
        if (block.timestamp > meta.deadline + REVEAL_WINDOW)   revert RevealPhaseClosed();
        if (bytes(answer).length > MAX_ANSWER_LENGTH)          revert AnswerTooLong();

        Entry storage e = entries[bountyId][msg.sender];
        if (e.commitment == 0)  revert NothingCommitted();
        if (e.revealed)         revert AlreadyRevealed();

        // Core verification: answer + salt + sender + bountyId must reproduce the stored hash.
        bytes32 expected = keccak256(abi.encodePacked(answer, salt, msg.sender, bountyId));
        if (expected != e.commitment) revert HashMismatch();

        e.answer   = answer;
        e.salt     = salt;
        e.revealed = true;

        emit Revealed(bountyId, msg.sender, answer, salt);
    }

    // ─── Views ─────────────────────────────────────────────────────────────────

    /**
     * @notice Compute the commitment hash (use off-chain or in tests).
     */
    function makeCommitment(
        string calldata answer,
        bytes32 salt,
        address participant,
        uint256 bountyId
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(answer, salt, participant, bountyId));
    }

    /**
     * @notice Current phase for a bounty.
     *         0 = commit open, 1 = reveal open, 2 = closed / not registered.
     */
    function currentPhase(uint256 bountyId) external view returns (uint8) {
        BountyMeta storage meta = bountyMeta[bountyId];
        if (!meta.registered)                                return 2;
        if (block.timestamp < meta.deadline)                 return 0;
        if (block.timestamp <= meta.deadline + REVEAL_WINDOW) return 1;
        return 2;
    }

    /// @notice True only if the participant committed AND successfully revealed.
    function hasRevealed(uint256 bountyId, address participant) external view returns (bool) {
        return entries[bountyId][participant].revealed;
    }

    /**
     * @notice Returns the revealed answer for a participant.
     *         Reverts if not yet revealed — AIJudge should call this to gate judging.
     */
    function getAnswer(uint256 bountyId, address participant) external view returns (string memory) {
        Entry storage e = entries[bountyId][participant];
        if (!e.revealed) revert NotRevealedYet();
        return e.answer;
    }
}
