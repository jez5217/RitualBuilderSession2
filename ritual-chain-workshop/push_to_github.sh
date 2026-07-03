#!/bin/bash
set -e

echo "=== Starting GitHub Push Script ==="
echo ""

# Navigate to the repo directory
cd /ritual-chain-workshop
echo "[1/4] Working directory: $(pwd)"

# Step 1: Set remote origin
echo ""
echo "[2/4] Setting remote origin..."
git remote remove origin 2>/dev/null || echo "No existing remote to remove."
git remote add origin https://github.com/jez5217/ritualencryptedbountyjudge.git
echo "Remote origin set to: $(git remote get-url origin)"

# Step 2: Stage all changes
echo ""
echo "[3/4] Staging all changes (git add -A)..."
git add -A
echo "Staged files:"
git status --short

# Step 3: Commit
echo ""
echo "[4/4] Committing..."
git commit -m "feat: TEE-encrypted commit-reveal bounty judge with Ritual LLM batch judging" || echo "Nothing new to commit (working tree clean)."

# Step 4: Push to main
echo ""
echo "[5/5] Pushing to main branch..."
git push -u origin main

echo ""
echo "=== Push Complete ==="
