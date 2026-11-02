# v2rayN WARP — personal build

Based on upstream v2rayN 7.17.3 (GPL-3.0). Adds a **WARP** checkbox beside System Proxy in the status bar.

- Off: the selected profile uses its normal connection.
- On: `client → WARP MASQUE/HTTP2 → selected proxy server → destination`.
- WARP runs inside the app's Xray process, without the old localhost helper.
- Works with regular Xray VLESS, VMess, Trojan, Shadowsocks, SOCKS and HTTP profiles. Other cores, custom configs and localhost helper profiles display an error instead of silently ignoring WARP.
- Existing direct/bypass routing rules stay direct. This checkbox changes how proxy servers are reached, not which destinations are routed to the proxy.
- Real-delay and download tests use the same WARP setting. A basic TCP ping is not a test of the full chain.

## macOS personal setup

`dist/v2rayN WARP.app` is a separate, self-contained Apple Silicon build. The application uses `~/Library/Application Support/v2rayN-WARP`, a separate process name and local port **10818**. It does not replace the installed app.

Run `python3 setup-personal.py` once on the original Mac. This copies the existing profiles and subscription settings into the private application-data directory and imports only the MASQUE WARP outbound from the existing helper. It does not embed credentials in the source tree or app bundle. Existing personal data is never overwritten by this setup script.

Open the personal app, select the actual server profile, and tick **WARP**. For other applications to use it, select Set system proxy or connect them to `127.0.0.1:10818`. Keep only one app responsible for the system proxy/TUN setting at a time. For testing alongside the existing client, this build starts with system proxy unchanged and TUN off.

The physical Ethernet/Wi-Fi interface is selected when generating the config, and only the WARP socket binds to it. After switching networks, reload the connection. A missing WARP profile or incompatible selected core stops this build's previous connection and displays an error. It does not fall back to an unprotected direct server socket when WARP is enabled.

To use another registration, replace the private `guiConfigs/warp-entry.private.json` with an Xray MASQUE WARP outbound (or a full Xray config containing one). Keep permissions owner-only. This build does not register a new WARP account automatically. Updating the application from upstream would remove the custom checkbox; use builds from this fork.

## Build and checks

```sh
git submodule update --init --depth 1
dotnet restore v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj -r osx-arm64 -p:Configuration=Release
dotnet publish v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj -c Release -r osx-arm64 --self-contained true -o dist/publish
dotnet run --project tests/WarpChain.Tests.csproj
python3 package-personal-macos.py --core-bin-dir /path/to/official/bin --xray /path/to/recent/xray
```

Bundle a recent official Xray core with MASQUE support (the personal build uses 26.10.21). `WarpChainConfig` tests check chain direction, preservation of direct routing and DNS, existing chains, interface binding and rejection of localhost/invalid profiles. An unsigned/ad-hoc signed personal macOS app is not a notarized public release.

Verified on the original Mac on 3 November 2026: enabling the actual checkbox produced a WARP first-hop socket, with no direct origin-server socket from that core; the final HTTPS egress was the user's origin server in Germany. A 1 MiB download and 128 KiB upload succeeded. Disabling the checkbox removed the WARP outbound and dialer and HTTPS still worked through the selected server. The user completed macOS Privacy & Security approval for the locally built executable before the successful run. This is a connectivity check, not a speed benchmark. Windows UI is wired but has not been built or tested here.

## استفادهٔ کوتاه

برنامهٔ **v2rayN WARP** را باز کن، پروفایل واقعی سرور را انتخاب کن و کنار تنظیم پروکسی تیک **WARP** را بزن. تیک روشن: دستگاه ← WARP ← سرور. تیک خاموش: اتصال عادی به همان سرور. تنظیمات برنامهٔ قبلی جدا می‌ماند. گزینهٔ localhost مربوط به واسط قدیمی را برای این تیک انتخاب نکن.
