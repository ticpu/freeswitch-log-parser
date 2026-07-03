Perform a release of freeswitch-log-parser.

Optional override: $ARGUMENTS (format: vX.Y.Z). If provided, use that version.

## Version determination

1. Find the last release tag (`git tag --sort=-v:refname | head -1`).
2. Examine commits since that tag to classify the release type:
   - **Patch**: only bug fixes, dependency bumps, build changes, docs.
   - **Minor**: new features (`feat:`), new public API surface.
   - **Major**: breaking API changes, removed public items, incompatible config changes.
3. Bump the version accordingly. If **major**, stop and confirm before proceeding.

## Pre-release checks

Run in sequence — stop and report on any failure:

```sh
cargo fmt --all
cargo clippy --fix --allow-dirty --message-format=short
cargo check --features cli
cargo check --features tui
cargo test --release -- --quiet
cargo semver-checks check-release
cargo publish --dry-run
```

## Steps

1. Bump `version` in `Cargo.toml`.

2. Run pre-release checks above.

3. Draft a changelog from `git log --oneline <last-tag>..HEAD`.

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - No git hashes, no raw commit subjects, no co-author lines.

   Tag annotation format:
   ```
   vX.Y.Z

   New features:
   - what changed

   Bug fixes:
   - what was fixed

   Build:
   - what changed
   ```

4. Stage, commit, tag, push:

```sh
git add Cargo.toml
git commit -m "release: vX.Y.Z"
git tag -as vX.Y.Z -m "$(cat <<'EOF'
vX.Y.Z

<changelog>
EOF
)"
git push && git push --tags
```

5. Publish:

```sh
cargo publish
```

6. Report the tag and changelog.

## Important

- **Never commit Cargo.lock** — library crate, stays gitignored.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
- **`cargo publish --dry-run` must pass** before real publish.
