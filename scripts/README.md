# 📦 Publishing Scripts

Simple shell scripts for version management and npm publishing.

## Quick Start

```bash
# Check current version
npm run version

# Release a patch version (0.1.0 -> 0.1.1)
npm run release:patch

# Release a minor version (0.1.0 -> 0.2.0)
npm run release:minor
```

## Scripts

### `version.sh` - Version Management
```bash
./scripts/version.sh current  # Show current version
./scripts/version.sh patch    # 0.1.0 -> 0.1.1
./scripts/version.sh minor    # 0.1.0 -> 0.2.0  
./scripts/version.sh major    # 0.1.0 -> 1.0.0
```

### `publish.sh` - NPM Publishing
```bash
./scripts/publish.sh          # Build and publish to npm
```

- Checks npm authentication
- Prevents publishing existing versions
- Builds and validates package
- Runs linting
- Publishes to npm

### `release.sh` - Complete Release
```bash
./scripts/release.sh patch    # Version bump + publish
./scripts/release.sh minor    # Version bump + publish
./scripts/release.sh major    # Version bump + publish
```

**What it does:**
1. Updates version in `package.json` files
2. Commits version change to git
3. Builds and publishes to npm
4. Creates git tag
5. Pushes changes and tags

## NPM Scripts

```bash
npm run version              # Show current version
npm run version:patch        # Bump patch version
npm run version:minor        # Bump minor version
npm run version:major        # Bump major version
npm run publish              # Publish to npm
npm run release:patch        # Complete patch release
npm run release:minor        # Complete minor release
npm run release:major        # Complete major release
```

## Requirements

- Node.js and npm installed
- Logged in to npm: `npm login`
- Git repository (for release script)

## Example Workflow

```bash
# 1. Make your changes
# 2. Commit your changes
git add .
git commit -m "feat: add new feature"

# 3. Release
npm run release:patch
```

That's it! 🎉