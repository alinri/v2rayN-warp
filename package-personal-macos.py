#!/usr/bin/env python3
"""Package compiled app and official cores without including user configuration."""
import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--publish-dir', type=Path, default=Path('dist/publish'))
p.add_argument('--core-bin-dir', type=Path, required=True, help='Official v2rayN core bin directory')
p.add_argument('--xray', type=Path, required=True, help='Recent official Xray macOS arm64 executable with MASQUE support')
p.add_argument('--output', type=Path, default=Path('dist/v2rayN WARP.app'))
args = p.parse_args()
contents = args.output / 'Contents'
macos = contents / 'MacOS'
resources = contents / 'Resources'
macos.mkdir(parents=True, exist_ok=True)
resources.mkdir(parents=True, exist_ok=True)
shutil.copytree(args.publish_dir, macos, dirs_exist_ok=True)
shutil.copytree(args.core_bin_dir, macos / 'bin', dirs_exist_ok=True)
shutil.copy2(args.xray, macos / 'bin/xray/xray')
(macos / 'NotStoreConfigHere.txt').write_text('Store personal configuration outside the bundle.\n')
icon = args.publish_dir / 'v2rayN.icns'
if not icon.exists():
    icon = Path(__file__).parent / 'v2rayN/v2rayN.Desktop/v2rayN.icns'
shutil.copy2(icon, resources / 'AppIcon.icns')
shutil.copy2(Path(__file__).parent / 'LICENSE', resources / 'LICENSE-v2rayN.txt')
info = dict(CFBundleDevelopmentRegion='English', CFBundleDisplayName='v2rayN WARP',
            CFBundleExecutable='v2rayN', CFBundleIconFile='AppIcon',
            CFBundleIdentifier='shop.mislog.v2rayn-warp', CFBundleName='v2rayN WARP',
            CFBundlePackageType='APPL', CFBundleShortVersionString='7.17.3', CFBundleVersion='7.17.3.4',
            NSHighResolutionCapable=True, LSMinimumSystemVersion='12.7')
with (contents / 'Info.plist').open('wb') as f:
    plistlib.dump(info, f)
# Ad-hoc sign the enclosing app and nested components in the upstream bundle layout.
subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(args.output)], check=True)
subprocess.run(['codesign', '--verify', '--deep', '--strict', str(args.output)], check=True)
print(args.output.resolve())
