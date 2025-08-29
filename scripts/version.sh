#!/bin/bash

# Simple Version Management Script
set -e

# Get current version
get_version() {
    node -p "require('./package.json').version"
}

# Update version in package.json
update_version() {
    local new_version=$1
    # Update main package.json
    sed -i.bak "s/\"version\": \".*\"/\"version\": \"$new_version\"/" package.json
    rm -f package.json.bak
    
    # Update example package.json if exists
    if [[ -f "example/package.json" ]]; then
        sed -i.bak "s/@a-cube-io\/expo-mutual-tls\": \".*\"/@a-cube-io\/expo-mutual-tls\": \"$new_version\"/" example/package.json
        rm -f example/package.json.bak
    fi
    
    echo "✅ Updated version to $new_version"
}

# Increment version
increment_version() {
    local current_version=$(get_version)
    local type=$1
    local IFS='.'
    local ver=($current_version)
    
    case $type in
        "patch")
            local new_version="${ver[0]}.${ver[1]}.$((${ver[2]} + 1))"
            ;;
        "minor")
            local new_version="${ver[0]}.$((${ver[1]} + 1)).0"
            ;;
        "major")
            local new_version="$((${ver[0]} + 1)).0.0"
            ;;
        *)
            echo "❌ Usage: $0 [patch|minor|major|current]"
            exit 1
            ;;
    esac
    
    update_version "$new_version"
    echo "$new_version"
}

# Main
cd "$(dirname "$0")/.."

case ${1:-""} in
    "current")
        get_version
        ;;
    "patch"|"minor"|"major")
        increment_version "$1"
        ;;
    *)
        echo "Usage: $0 [current|patch|minor|major]"
        echo "Current version: $(get_version)"
        exit 1
        ;;
esac