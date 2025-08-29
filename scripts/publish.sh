#!/bin/bash

# Simple Publishing Script
set -e

echo "🚀 Publishing @a-cube-io/expo-mutual-tls..."

# Change to package root
cd "$(dirname "$0")/.."

# Check if logged in to npm
if ! npm whoami > /dev/null 2>&1; then
    echo "❌ Not logged in to npm. Run: npm login"
    exit 1
fi

# Get current version
VERSION=$(node -p "require('./package.json').version")
echo "📦 Version: $VERSION"

# Check if version already exists
if npm view "@a-cube-io/expo-mutual-tls@$VERSION" version > /dev/null 2>&1; then
    echo "❌ Version $VERSION already exists on npm"
    exit 1
fi

# Clean and build
echo "🧹 Cleaning..."
npm run clean > /dev/null 2>&1 || true
#rm -rf build

#echo "🔨 Building..."
#npm run build

# Check build output
#if [[ ! -f "build/index.js" ]] || [[ ! -f "build/index.d.ts" ]]; then
#    echo "❌ Build failed - missing output files"
#    exit 1
#fi

# Skip lint for now (ESLint config issues)
echo "🔍 Skipping lint..."
npm run lint

# Confirm publish
echo ""
echo "Ready to publish @a-cube-io/expo-mutual-tls@$VERSION"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 0
fi

# Publish
echo "📤 Publishing..."
npm publish

echo "✅ Published @a-cube-io/expo-mutual-tls@$VERSION"
echo "🔗 https://www.npmjs.com/package/@a-cube-io/expo-mutual-tls"