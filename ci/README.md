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

Validation: all four native-runner CI jobs (including cross-compilation for the
other CPU architecture) passed in the [initial build-only run](https://github.com/alinri/v2rayN-warp/actions/runs/41586418633)
on 3 November 2026. Its Actions Artifacts count was zero. Local macOS ZIP
packaging, bundled-core presence, SHA-256 and private-data exclusion were also
checked. Release state transitions and refusal to overwrite published assets
have unit coverage; publishing itself is triggered by a tag push.

The personal build now includes the pinned SNI spoofing helper on macOS ARM64,
macOS Intel and Windows x64. Windows ARM64 builds omit it and report the feature
as unavailable. `ci/build_sni.py` builds from vendored Rust source with a locked
Cargo dependency graph; Windows additionally verifies the official WinDivert
archive before packaging its signed driver. Helper source, upstream revision and
licenses accompany the binary. See [the Persian usage guide](../SNI-SPOOFING.fa.md).
All four builds including the SNI helper checks passed in the
[SNI build-only run](https://github.com/alinri/v2rayN-warp/actions/runs/41729708566)
on 4 November 2026. Its Actions Artifacts list was empty; Release publishing
was skipped. macOS ARM64, macOS Intel and Windows x64 execute the matching Rust
unit tests and unprivileged helper control-channel smoke test. Windows ARM64
builds the desktop without the unavailable SNI helper. Real packet injection and
WS/XHTTP transfer were checked locally on macOS ARM64; Windows and Intel packet
injection still need tests on those systems.

The SNI Real Delay regression fix also passed all four platform builds in
[this build-only run](https://github.com/alinri/v2rayN-warp/actions/runs/41778190347).
Its Actions Artifacts list was empty and publishing was skipped. Regression tests
cover mixed WS/XHTTP batches, distinct destinations, TLS and routing preservation,
and isolation of unsupported or failed nodes. Local UI checks verified individual
and batch Real Delay with SNI enabled, temporary-listener cleanup and continued
traffic on the active connection.
