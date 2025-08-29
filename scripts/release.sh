#!/bin/bash

# Simple Release Script
set -e

# Usage
if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [patch|minor|major]"
    echo "Current version: $(./scripts/version.sh current)"
    exit 1
fi

VERSION_TYPE=$1

# Change to package root
cd "$(dirname "$0")/.."

echo "🚀 Starting release process..."

# Update version
echo "📝 Updating version ($VERSION_TYPE)..."
NEW_VERSION=$(./scripts/version.sh "$VERSION_TYPE")

# Commit version change
if [[ -d ".git" ]]; then
    echo "📋 Committing version change..."
    git add package.json example/package.json 2>/dev/null || git add package.json
    git commit -m "chore: bump version to $NEW_VERSION" || echo "⚠️ Nothing to commit"
fi

# Publish
echo "📤 Publishing..."
./scripts/publish.sh

# Create git tag
if [[ -d ".git" ]]; then
    echo "🏷️ Creating git tag..."
    git tag "v$NEW_VERSION"
    
    echo "🔀 Pushing to git..."
    git push || echo "⚠️ Failed to push commits"
    git push --tags || echo "⚠️ Failed to push tags"
fi

echo "🎉 Release $NEW_VERSION complete!"