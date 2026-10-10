# Releasing

Releases are cut from `main` by pushing a version tag. The workflow (`.github/workflows/release.yml`) runs the full test suite, builds both images, refuses to publish if either has a fixable CRITICAL vulnerability, pushes them to GitHub Container Registry with build provenance and an SBOM, signs them, and creates the GitHub release from the changelog.

## Cut a release

1. Make sure `main` is green (CI and Security workflows).
2. In `CHANGELOG.md`, move the entries under `## [Unreleased]` into a new dated section, for example `## [0.4.0] - 2026-10-10`. The workflow fails if the tag has no such dated section, so a release cannot go out without notes.
3. Commit and push that change.
4. Tag and push:
   ```bash
   git tag -a v0.4.0 -m "v0.4.0"
   git push origin v0.4.0
   ```
5. Watch **Actions > Release**. When it finishes, the release page lists the images with their digests.

To rehearse without publishing anything, run **Actions > Release > Run workflow** on `main`. It tests, builds and scans both images and stops before login and push.

Versions follow [Semantic Versioning](https://semver.org): a database migration or a configuration change that needs action is at least a minor version; a fix with neither is a patch.

## Use a release

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.images.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.images.yml up -d
```

`ASM_VERSION` (default `latest`) selects the release. For a reproducible deployment pin the digests printed in the release notes in `.env.docker`:

```text
ASM_BACKEND_IMAGE=ghcr.io/turlafsb/asm-backend@sha256:<digest>
ASM_FRONTEND_IMAGE=ghcr.io/turlafsb/asm-frontend@sha256:<digest>
```

Database migrations run automatically on start (the `migrate` service). Take a backup first and read the release's "Changed" section; see [Upgrading](../README.md#upgrading).

## Verify an image

Images are signed with Sigstore keyless signing, bound to this repository's release workflow. Verify before you run one:

```bash
cosign verify ghcr.io/turlafsb/asm-backend@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/TurlaFSB/ASM-/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A failed verification means the image was not produced by this repository's release workflow; do not run it.

## Roll back

Set `ASM_VERSION` (or the digests) to the previous release and run the two compose commands above. A migration that already ran is not undone by older images: restore the backup taken before the upgrade if the previous version cannot read the new schema (`restore.sh`, see [Backup and restore](../README.md#backup-and-restore)).

## First publish

GitHub creates the packages as private on the first push. Open the repository's **Packages**, choose each image, then **Package settings > Change visibility > Public**, so others can pull without logging in.
