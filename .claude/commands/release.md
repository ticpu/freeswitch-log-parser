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

4. Commit the bump and build the tag locally — nothing is pushed yet. The tag
   sits on a detached child commit that pins `Cargo.lock`, so the lock never
   lands on master while the released binaries still build from an exact
   dependency set:

```sh
git add Cargo.toml
git commit -m "release: vX.Y.Z"
git checkout --detach
git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for vX.Y.Z"
git tag -as vX.Y.Z -m "$(cat <<'EOF'
vX.Y.Z

<changelog>
EOF
)"
git switch master
```

   Run these as **separate** commands, never chained with `&&`. If a chained
   command is rejected part-way — a hook, a denied permission — the untried
   half is silently skipped, and the failure mode here is committing
   `Cargo.lock` onto master because the `git checkout --detach` never ran.
   After `git checkout --detach`, confirm with `git symbolic-ref -q HEAD`
   (it must fail) before staging the lock. The `pre-commit` hook rejects a
   staged `Cargo.lock` on a branch and `pre-push` rejects a branch tip that
   tracks it, but neither replaces checking that the detach took.

5. Push master, wait for CI green:

```sh
git push
gh run watch "$(gh run list --workflow=ci.yml -b master -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   No run within a couple of minutes: check the `Actions` component at
   `https://www.githubstatus.com/api/v2/components.json` — during an outage no
   run is created and missed events are never backfilled. Stop and report.

   Red: fix on master, rebuild the tag onto the new head, restart this step.

6. Push the tag, wait for the release workflow:

```sh
git push origin vX.Y.Z
gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   It builds the amd64/arm64 `.deb`s and binaries and creates the GitHub release
   using the tag annotation as its body. The release is left a **draft** — step 7
   signs its assets and publishes it.

   Red, or no run created: stop. Never retag — a fix is a new patch release. If
   the workflow never ran because Actions was down, dispatch it once Actions
   recovers (`gh workflow run release.yml --ref vX.Y.Z`) and wait for that run.

7. Sign the assets and publish the release:

```sh
./sign-release.sh --dry-run
./sign-release.sh
```

   It detach-signs every asset — `SHA256SUMS` included — with the key from
   `git config user.signingkey`, verifies each signature, uploads the `.asc`
   files, then clears the draft flag. `--dry-run` signs into
   `scratch/release-sign-vX.Y.Z` and uploads nothing, which is how the key and
   the asset list get checked before the real run.

   Nothing may be published unsigned: apt.ticpu.net verifies each asset's
   signature on ingest, and with release immutability enabled a published
   release's assets can no longer be replaced.

8. Publish, from the tagged commit:

```sh
git checkout vX.Y.Z
cargo publish
git switch master
```

   `git switch master` deletes the working-tree `Cargo.lock` (untracked there);
   the next cargo command regenerates it.

9. Report the tag, the changelog, the CI runs that gated the publish, and the
   crates.io version.

## Important

- **Never publish a commit CI has not run on.** If the tree changed after the
  checks — a rebase, a hand-resolved conflict, a dependency that resolved
  differently — the earlier green run does not cover it. Re-run the checks and
  go back to step 5.
- **Ask before publishing when anything deviated from these steps.** An outage,
  a rebase, a skipped step, a red-then-fixed run: report the state and let me
  decide.
- **Cargo.lock never reaches master** — library crate, stays gitignored there. It
  exists only on the tag's own commit, so a release build is reproducible.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
