#!/usr/bin/env bash
#
# Setup extras/ directory from a specific release branch
# Usage: ./scripts/setup_release.sh release-2.17
#

set -e

RELEASE_BRANCH=${1:-}
EXTRAS_DIR=${EXTRAS_DIR:-extras}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [ -z "$RELEASE_BRANCH" ]; then
    echo -e "${RED}Error: Release branch required${NC}"
    echo ""
    echo "Usage: $0 <release-branch>"
    echo ""
    echo "Examples:"
    echo "  $0 release-2.17"
    echo "  $0 release-2.16"
    echo ""
    exit 1
fi

echo -e "${BLUE}Setting up extras/ from ${RELEASE_BRANCH}...${NC}"

# Fetch latest remote refs to ensure we have up-to-date branches
echo -e "${BLUE}Fetching latest remote refs...${NC}"
git fetch origin

# Check if release branch exists
if ! git rev-parse --verify "origin/${RELEASE_BRANCH}" > /dev/null 2>&1; then
    echo -e "${RED}Error: Release branch 'origin/${RELEASE_BRANCH}' not found${NC}"
    echo ""
    echo "Available release branches:"
    git branch -r | grep -E 'origin/release-' | sed 's|origin/||' | sort -V
    exit 1
fi

# Backup current extras/ if it exists
if [ -d "$EXTRAS_DIR" ] && [ "$(ls -A $EXTRAS_DIR 2>/dev/null)" ]; then
    echo -e "${YELLOW}Backing up current extras/ to extras-backup/${NC}"
    mkdir -p extras-backup
    rm -rf extras-backup/*
    cp -r "$EXTRAS_DIR"/* extras-backup/ 2>/dev/null || true
fi

# Clean and recreate extras directory
rm -rf "$EXTRAS_DIR"
mkdir -p "$EXTRAS_DIR"

# Copy extras/ from release branch
echo -e "${BLUE}Copying extras/ from ${RELEASE_BRANCH}...${NC}"
if ! git show "origin/${RELEASE_BRANCH}:extras/" > /dev/null 2>&1; then
    echo -e "${RED}Error: extras/ not found in ${RELEASE_BRANCH}${NC}"
    exit 1
fi

for file in $(git ls-tree --name-only "origin/${RELEASE_BRANCH}:extras/"); do
    git show "origin/${RELEASE_BRANCH}:extras/$file" > "$EXTRAS_DIR/$file"
    echo -e "${GREEN}  ✓ ${file}${NC}"
done

# Copy ICSP config if it exists in release branch
if git show "origin/${RELEASE_BRANCH}:icsp-config.json" > /dev/null 2>&1; then
    echo -e "${GREEN}Copying icsp-config.json from ${RELEASE_BRANCH}${NC}"
    git show "origin/${RELEASE_BRANCH}:icsp-config.json" > icsp-config.json
fi

echo ""
echo -e "${GREEN}✓ Setup complete!${NC}"
echo -e "${GREEN}  Extras from: ${RELEASE_BRANCH}${NC}"
echo -e "${GREEN}  Files: $(ls $EXTRAS_DIR | wc -l | tr -d ' ')${NC}"
echo ""
echo -e "${YELLOW}You can now run:${NC}"
echo "  make scan-cves"
echo "  make verify-images"
echo "  make slack-cve-report"
