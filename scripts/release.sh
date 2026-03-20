#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh [patch|minor|beta]
# Default: patch

BUMP_TYPE="${1:-patch}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

DRY_RUN="${DRY_RUN:-0}"
SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-0}"

# Validate bump type
if [[ "$BUMP_TYPE" != "patch" && "$BUMP_TYPE" != "minor" && "$BUMP_TYPE" != "beta" ]]; then
    error "Invalid bump type: $BUMP_TYPE. Use 'patch', 'minor', or 'beta'."
fi

info "Bump type: $BUMP_TYPE"

# =============================================================================
# Preflight checks
# =============================================================================

# Resolve last tag (local git operation — always runs)
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

if [[ "$SKIP_PREFLIGHT" != "1" ]]; then

info "Running preflight checks..."

# Check we're in a git repository
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    error "Not in a git repository"
fi

# Check we're on the default branch (main)
DEFAULT_BRANCH="main"
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]]; then
    error "Not on default branch. Current: $CURRENT_BRANCH, Expected: $DEFAULT_BRANCH"
fi

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --staged --quiet; then
    error "Working directory has uncommitted changes. Commit or stash them first."
fi

# Check for untracked files (warning only)
UNTRACKED=$(git ls-files --others --exclude-standard)
if [[ -n "$UNTRACKED" ]]; then
    warn "Untracked files present (continuing anyway):"
    echo "$UNTRACKED" | head -5
fi

# Fetch latest from remote
info "Fetching latest from origin..."
git fetch origin "$DEFAULT_BRANCH" --tags

# Check if local branch is up to date with remote
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse "origin/$DEFAULT_BRANCH")
if [[ "$LOCAL_COMMIT" != "$REMOTE_COMMIT" ]]; then
    error "Local branch is not up to date with origin/$DEFAULT_BRANCH. Run 'git pull' first."
fi

# Check if there are commits since last tag
if [[ -n "$LAST_TAG" ]]; then
    COMMITS_SINCE_TAG=$(git rev-list "$LAST_TAG"..HEAD --count)
    if [[ "$COMMITS_SINCE_TAG" -eq 0 ]]; then
        error "No commits since last tag ($LAST_TAG). Nothing to release."
    fi
    info "Commits since $LAST_TAG: $COMMITS_SINCE_TAG"
fi

info "✓ All preflight checks passed"

fi # end SKIP_PREFLIGHT

# =============================================================================
# Calculate new version
# =============================================================================

if [[ -z "$LAST_TAG" ]]; then
    # No existing tags, start at v0.1.0
    NEW_VERSION="v0.1.0"
    if [[ "$BUMP_TYPE" == "beta" ]]; then
        NEW_VERSION="v0.1.0-beta.1"
    fi
    info "No existing tags found. Starting at $NEW_VERSION"
else
    if [[ "$BUMP_TYPE" == "beta" ]]; then
        # Find the last stable tag (ignore -beta.* tags) as the base
        LAST_STABLE_TAG=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -v '\-' | sort -V | tail -1 || true)
        if [[ -z "$LAST_STABLE_TAG" ]]; then
            LAST_STABLE_TAG="v0.0.0"
        fi
        VERSION="${LAST_STABLE_TAG#v}"
        IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
        PATCH=$((PATCH + 1))
        BASE_VERSION="${MAJOR}.${MINOR}.${PATCH}"
        # Find highest existing beta number for this base version
        LATEST_BETA=$(git tag -l "v${BASE_VERSION}-beta.*" | sort -V | tail -1 || true)
        if [[ -z "$LATEST_BETA" ]]; then
            BETA_NUM=1
        else
            BETA_NUM=$(echo "$LATEST_BETA" | sed 's/.*-beta\.\([0-9]*\)$/\1/')
            BETA_NUM=$((BETA_NUM + 1))
        fi
        NEW_VERSION="v${BASE_VERSION}-beta.${BETA_NUM}"
        info "Beta tag: $LAST_STABLE_TAG → $NEW_VERSION"
    else
        # Parse current version (strip 'v' prefix and any pre-release suffix)
        VERSION="${LAST_TAG#v}"
        VERSION="${VERSION%%-*}"  # strip pre-release suffix if present
        IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

        # Validate parsed version
        if [[ -z "$MAJOR" || -z "$MINOR" || -z "$PATCH" ]]; then
            error "Failed to parse version from tag: $LAST_TAG"
        fi

        # Increment based on bump type
        case "$BUMP_TYPE" in
            patch)
                PATCH=$((PATCH + 1))
                ;;
            minor)
                MINOR=$((MINOR + 1))
                PATCH=0
                ;;
        esac

        NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"
        info "Version bump: $LAST_TAG → $NEW_VERSION"
    fi
fi

if [[ "$DRY_RUN" == "1" ]]; then
    info "Dry run: would release $NEW_VERSION"
    exit 0
fi

# =============================================================================
# Confirm and create tag
# =============================================================================

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Ready to release: $NEW_VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Create and push tag $NEW_VERSION? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Aborted."
    exit 0
fi

# Create annotated tag
info "Creating tag $NEW_VERSION..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

# Push tag to origin
info "Pushing tag to origin..."
git push origin "$NEW_VERSION"

echo ""
info "✓ Released $NEW_VERSION"
info "GitHub Actions will now build and publish the release."
info "Watch progress at: https://github.com/GreyhavenHQ/greyproxy/actions"
