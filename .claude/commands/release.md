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

4. Commit the bump on master and push it:

```sh
git add Cargo.toml
git commit -m "release: vX.Y.Z"
git push
```

5. Tag a detached child commit that pins `Cargo.lock`. The tag is the only ref
   that reaches it, so the lock never lands on master while the released
   binaries still build from an exact dependency set:

```sh
git checkout --detach
git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for vX.Y.Z"
git tag -as vX.Y.Z -m "$(cat <<'EOF'
vX.Y.Z

<changelog>
EOF
)"
git push origin vX.Y.Z
cargo publish
git switch master
```

   `cargo publish` runs while still detached, so the published crate matches the
   tag exactly. `git switch master` deletes the working-tree `Cargo.lock` (it is
   untracked there); the next cargo command regenerates it.

6. Report the tag and changelog.

   Pushing the tag triggers `.github/workflows/release.yml`, which builds the
   amd64/arm64 `.deb`s and binaries and creates the GitHub release using the tag
   annotation as its body — so the changelog above is what the release page shows.

## Important

- **Cargo.lock never reaches master** — library crate, stays gitignored there. It
  exists only on the tag's own commit, so a release build is reproducible.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
- **`cargo publish --dry-run` must pass** before real publish.
