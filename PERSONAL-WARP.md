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

To use another registration, replace the private `guiConfigs/warp-entry.private.json` with an Xray MASQUE WARP outbound (or a full Xray config containing one). Keep permissions owner-only. The desktop Create WARP dialog can register a separate MASQUE device after explicit acceptance of Cloudflare terms. Updating the application from upstream would remove the custom checkbox; use builds from this fork.

## Create a WARP configuration inside the app

In the desktop status bar, click **Create WARP** beside the WARP checkbox.

1. Keep **Use current proxy to register** enabled if the Cloudflare API is unreachable directly. A working selected proxy is required for this option; it uses this app's local mixed port. Uncheck it to use the normal network route.
2. Read the linked Cloudflare terms and explicitly accept them, then click **Create**. A separate device is registered, so the active WARP device is not re-enrolled or changed.
3. A fresh P-256 key is generated locally and enrolled for MASQUE. Only public keys are sent to Cloudflare. The result uses HTTP/2 on the dedicated H2 edge, Safari fingerprint and endpoint certificate pinning.
4. The app saves a private draft and runs an independent connectivity test over the physical interface, requiring `warp=on` or `warp=plus`. **Test** retries that test without creating another device.
5. After success, **Use this config** saves the tested profile and backs up the previous one. If the main WARP checkbox is already enabled, the selected proxy reconnects through the new profile; otherwise enable it when ready.

The existing profile is loaded for testing when no draft exists. The status explicitly identifies whether the current profile or a draft was loaded. Creating a profile does not silently replace the active one. Closing during creation/testing cancels the operation. Failed enrollment attempts trigger best-effort cleanup of only the device created by that attempt.

Drafts, active profiles, backups and generated runtime configurations are written atomically with owner-only file permissions on macOS/Linux. No registration token or private key is printed in UI logs, committed to source or embedded in the application bundle. Keep private configuration files out of shared folders. Closing the dialog retains a successfully saved draft for a later test.

The registration API is not a stable public Cloudflare developer API and can change or rate-limit requests. Errors leave the current active profile in place. Protocol references: [3x-ui's registration implementation](https://github.com/MHSanaei/3x-ui/blob/main/internal/web/service/integration/warp.go), [Xray's MASQUE WARP guide](https://xtls.github.io/en/document/level-2/warp.html), and [usque's HTTP/2 endpoints](https://github.com/Diniboy1123/usque/wiki/HTTP-2-support).

The creation dialog is implemented for the Avalonia desktop build used on this Mac. The Windows WPF checkbox remains wired; a Windows creation dialog has not been added or tested here.

## Create a WARP+ configuration

The desktop dialog also accepts an existing paid WARP+ subscription key. Open **Create WARP**, paste your key into the masked **WARP+ license key** field, accept Cloudflare's terms and click **Create**. Leave the key blank to create free WARP instead. You need an available device slot on your subscription; the app does not remove any of your other devices. See [Cloudflare's license instructions](https://developers.cloudflare.com/warp-client/get-started/linux/) and [WARP+ subscription information](https://developers.cloudflare.com/warp-client/warp-modes/).

The key is sent over HTTPS only to Cloudflare's registration API to link the separate newly created device. It is cleared from the input on Create and is not saved in configuration, backups or logs. The app does not retain the registration API token. You must enter the key again when creating another Plus device.

Before producing a Plus draft, the app reads the linked account and requires `warp_plus=true`. Its independent connection test then requires **`warp=plus`**, using only the new WARP outbound on the physical interface; it cannot mistake the selected server's WARP exit for the new first hop. A free `warp=on` result cannot pass a Plus test. Only after the **WARP+ test passed** status appears can **Use this config** replace the active profile, keeping a private backup. A rejected license or unconfirmed Plus account removes only the device created by that registration attempt; the active profile and other subscription devices are preserved. A successfully registered draft that fails the network test remains available for **Test** without registering another device.

The saved outbound tag records that a Plus proof is required, so reopening and testing a Plus draft still checks for Plus. The runtime chain uses the normal WARP tag and the same checkbox. This is a creation and connectivity check, not ongoing subscription monitoring or a speed guarantee.

WARP+ license attachment and rejection, independent account verification, the saved Plus requirement, strict trace checking, credential isolation and cleanup are covered by .NET 8 tests. During a live attempt on 3 November 2026, the user entered their license in the application. Registration reached the saved Plus draft, which requires the account API to have returned `warp_plus=true`, but the independent tunnel test returned `warp=on`. A repeat test and checks against both H2 edges (162.159.198.2 and 162.159.199.2), multiple trace hosts and IPv4/IPv6 trace destinations returned the same ordinary WARP status. H3 checks against 162.159.198.1 and 162.159.199.1 did not complete HTTPS successfully. The draft was retained for diagnostics and the active profile was preserved. Paid Plus connectivity has therefore **not** been verified; account entitlement and actual tunnel status must not be treated as equivalent. The user's subscription status in the official application is the next diagnostic check. No further device was registered during these checks.

## Build and checks

```sh
git submodule update --init --depth 1
dotnet restore v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj -r osx-arm64 -p:Configuration=Release
dotnet publish v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj -c Release -r osx-arm64 --self-contained true -o dist/publish
dotnet publish tests/WarpChain.Tests.csproj -c Release -r osx-arm64 --self-contained true -o dist/tests-net8
./dist/tests-net8/WarpChain.Tests
python3 package-personal-macos.py --core-bin-dir /path/to/official/bin --xray /path/to/recent/xray
```

Bundle a recent official Xray core with MASQUE support (the personal build uses 26.10.21). `WarpChainConfig` tests check chain direction, preservation of direct routing and DNS, existing chains, interface binding and rejection of localhost/invalid profiles. An unsigned/ad-hoc signed personal macOS app is not a notarized public release.

Verified on the original Mac on 3 November 2026: enabling the actual checkbox produced a WARP first-hop socket, with no direct origin-server socket from that core; the final HTTPS egress was the user's origin server in Germany. A 1 MiB download and 128 KiB upload succeeded. Disabling the checkbox removed the WARP outbound and dialer and HTTPS still worked through the selected server. The user completed macOS Privacy & Security approval for the locally built executable before the successful run. This is a connectivity check, not a speed benchmark. Windows UI is wired but has not been built or tested here.

## استفادهٔ کوتاه

برنامهٔ **v2rayN WARP** را باز کن، پروفایل واقعی سرور را انتخاب کن و کنار تنظیم پروکسی تیک **WARP** را بزن. تیک روشن: دستگاه ← WARP ← سرور. تیک خاموش: اتصال عادی به همان سرور. تنظیمات برنامهٔ قبلی جدا می‌ماند. گزینهٔ localhost مربوط به واسط قدیمی را برای این تیک انتخاب نکن.

برای ساخت کانفیگ تازه، کنار تیک WARP روی **Create WARP** بزن؛ شرایط Cloudflare را خودت بپذیر و **Create** را بزن. برنامه کانفیگ تازه را می‌سازد و تست می‌کند. پس از موفقیت **Use this config** را بزن؛ کانفیگ قبلی پشتیبان می‌شود. گزینهٔ **Use current proxy to register** برای ثبت از مسیر پروکسی فعال همین برنامه است.

برای **WARP+**، کلید اشتراک خودت را در کادر **WARP+ license key** وارد کن و سپس Create را بزن. کلید را در چت نفرست. پس از پیام **WARP+ test passed**، گزینهٔ **Use this config** را بزن. کلید در فایل‌ها ذخیره نمی‌شود و کانفیگ معمولی نمی‌تواند به‌جای Plus تأیید شود.

Generator verification: the registration flow is covered by mocked Cloudflare HTTP responses, current and legacy Xray `wg` output, enrollment key matching, response-error cleanup, and owner-only atomic storage/backup checks. Tests are published and executed using .NET 8, matching the desktop application runtime.

Fresh-device live verification completed on this Mac on 3 November 2026. The user accepted Cloudflare's terms and clicked Create in the corrected build. Registration and the independent WARP connectivity test succeeded. Use this config activated the saved draft; its settings matched the running core, and the previous distinct private key remained in an owner-only backup. Active, draft, backup and runtime files had mode 0600. With the main WARP checkbox enabled, the core's only established external TCP destination was the WARP HTTP/2 edge at 162.159.198.2:443, bound to en0. HTTPS through the application's local proxy returned a Germany exit with warp=on using the user's selected WARP CDN server profile. A 1 MiB download and 128 KiB synthetic upload both returned HTTP 200. The selected server, cleared system-proxy setting and disabled TUN setting were preserved. This verifies connectivity, not throughput performance or Windows behavior.
