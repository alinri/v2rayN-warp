# Personal releases

Push a new tag on a commit containing `personal-release.yml`:

```sh
git tag v7.17.3-warp.1
git push origin v7.17.3-warp.1
```

The workflow builds self-contained Avalonia desktop packages for macOS Apple
Silicon and Intel, and Windows x64 and ARM64. This uses the desktop UI on Windows
so WARP configuration creation is included. Each ZIP bundles the official proxy
cores, Xray 26.10.21 with a verified SHA-256, licenses and build metadata. No
personal configuration or WARP key is included. Windows uses its separate
`v2rayN-WARP` application-data directory; no one-time Mac setup script is run.

Builds upload ZIPs and individual SHA-256 files directly to a draft GitHub
Release using `GITHUB_TOKEN`. No Actions Artifacts or Actions cache is used,
including for transferring files between jobs. Only after all four builds pass
and all eight release assets exist does the final job publish the Release.
Failed builds leave a draft; rerunning failed jobs can finish it. Published
releases cannot be overwritten by rerunning this workflow. Tags containing `-`
are published as prereleases; other tags as normal releases.

Run the workflow manually on a branch for a build-only check: no Release or
Artifacts are created. Temporary build output is discarded with the runners.
The inherited upstream workflows are restricted to `2dust/v2rayN` and do not
run in this fork. No personal access token or additional secret is needed.

macOS bundles are ad-hoc signed, as with the existing local build. Apple
notarization and Windows code signing are not configured. Automatic in-app
updates from this fork are a separate feature; the stock updater still points
upstream. App-internal version remains the upstream base version; the exact
release tag and commit are recorded in `BUILD-INFO.json`.

When upgrading upstream, review the pinned core bundle commit and Xray version
in `package_release.py` along with its four official SHA-256 values. Keep the
personal workflow and upstream-only guards when resolving workflow conflicts.
