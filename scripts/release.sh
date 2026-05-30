#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh [patch|minor]
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

# Validate bump type
if [[ "$BUMP_TYPE" != "patch" && "$BUMP_TYPE" != "minor" ]]; then
    error "Invalid bump type: $BUMP_TYPE. Use 'patch' or 'minor' (or no argument for minor)."
fi

info "Bump type: $BUMP_TYPE"

# =============================================================================
# Preflight checks
# =============================================================================

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
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$LAST_TAG" ]]; then
    COMMITS_SINCE_TAG=$(git rev-list "$LAST_TAG"..HEAD --count)
    if [[ "$COMMITS_SINCE_TAG" -eq 0 ]]; then
        error "No commits since last tag ($LAST_TAG). Nothing to release."
    fi
    info "Commits since $LAST_TAG: $COMMITS_SINCE_TAG"
fi

# Check that tests pass
info "Running tests..."
if ! make test-ci; then
    error "Tests failed. Fix them before releasing."
fi

# Check that lint passes
info "Running linter..."
if ! make lint; then
    error "Lint failed. Fix issues before releasing."
fi

info "✓ All preflight checks passed"

# =============================================================================
# Calculate new version
# =============================================================================

if [[ -z "$LAST_TAG" ]]; then
    # No existing tags, start at v0.1.0
    NEW_VERSION="v0.1.0"
    info "No existing tags found. Starting at $NEW_VERSION"
else
    # Parse current version (strip 'v' prefix)
    VERSION="${LAST_TAG#v}"
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
info "Watch progress at: https://github.com/fencesandbox/fence/actions"
