#!/usr/bin/env bats
#
# Tests for scripts/release.sh version-bumping logic.
#
# Requirements:
#   brew install bats-core
#
# Run:
#   bats scripts/release_test.bats

SCRIPT="$BATS_TEST_DIRNAME/release.sh"

setup() {
    TEST_DIR=$(mktemp -d)
    cd "$TEST_DIR"
    git -c init.defaultBranch=main init -q
    git config user.email "test@example.com"
    git config user.name "Test"
    git commit --allow-empty -m "initial commit" -q
}

teardown() {
    rm -rf "$TEST_DIR"
}

# Helper: run the script with preflight and tagging disabled.
run_release() {
    SKIP_PREFLIGHT=1 DRY_RUN=1 bash "$SCRIPT" "$@"
}

# =============================================================================
# Input validation
# =============================================================================

@test "rejects invalid bump type" {
    run run_release foobar
    [ "$status" -ne 0 ]
    [[ "$output" == *"Invalid bump type"* ]]
}

@test "accepts patch bump type" {
    run run_release patch
    [ "$status" -eq 0 ]
}

@test "accepts minor bump type" {
    run run_release minor
    [ "$status" -eq 0 ]
}

@test "accepts beta bump type" {
    run run_release beta
    [ "$status" -eq 0 ]
}

@test "defaults to patch when no argument given" {
    run run_release
    [ "$status" -eq 0 ]
    [[ "$output" == *"Bump type: patch"* ]]
}

# =============================================================================
# No existing tags
# =============================================================================

@test "patch with no tags starts at v0.1.0" {
    run run_release patch
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.1.0"* ]]
}

@test "minor with no tags starts at v0.1.0" {
    run run_release minor
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.1.0"* ]]
}

@test "beta with no tags starts at v0.1.0-beta.1" {
    run run_release beta
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.1.0-beta.1"* ]]
}

# =============================================================================
# Patch bumps
# =============================================================================

@test "patch increments patch version" {
    git tag v0.3.0
    git commit --allow-empty -m "feat: something" -q
    run run_release patch
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.1"* ]]
}

@test "patch increments from higher patch number" {
    git tag v0.3.9
    git commit --allow-empty -m "feat: something" -q
    run run_release patch
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.10"* ]]
}

@test "patch strips pre-release suffix from last tag" {
    git tag v0.3.0
    git commit --allow-empty -m "beta work" -q
    git tag v0.3.1-beta.2
    git commit --allow-empty -m "more work" -q
    run run_release patch
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.2"* ]]
}

# =============================================================================
# Minor bumps
# =============================================================================

@test "minor increments minor and resets patch to zero" {
    git tag v0.3.2
    git commit --allow-empty -m "feat: something" -q
    run run_release minor
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.4.0"* ]]
}

@test "minor increments from v1.2.9" {
    git tag v1.2.9
    git commit --allow-empty -m "feat: something" -q
    run run_release minor
    [ "$status" -eq 0 ]
    [[ "$output" == *"v1.3.0"* ]]
}

# =============================================================================
# Beta bumps
# =============================================================================

@test "beta from stable tag produces beta.1 of next patch" {
    git tag v0.3.0
    git commit --allow-empty -m "feat: something" -q
    run run_release beta
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.1-beta.1"* ]]
}

@test "beta auto-increments to beta.2 when beta.1 exists" {
    git tag v0.3.0
    git tag v0.3.1-beta.1
    git commit --allow-empty -m "feat: something" -q
    run run_release beta
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.1-beta.2"* ]]
}

@test "beta auto-increments to beta.3 when beta.1 and beta.2 exist" {
    git tag v0.3.0
    git tag v0.3.1-beta.1
    git tag v0.3.1-beta.2
    git commit --allow-empty -m "feat: something" -q
    run run_release beta
    [ "$status" -eq 0 ]
    [[ "$output" == *"v0.3.1-beta.3"* ]]
}

@test "beta uses stable tag as base, not the latest beta tag" {
    git tag v0.2.0
    git tag v0.3.1-beta.1
    git commit --allow-empty -m "feat: something" -q
    run run_release beta
    [ "$status" -eq 0 ]
    # Base is v0.2.0 → next patch is v0.2.1, so beta is v0.2.1-beta.1
    [[ "$output" == *"v0.2.1-beta.1"* ]]
}
