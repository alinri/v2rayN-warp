"""Package clean CI output with pinned official cores; never copy user data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from release import RID_LABELS

CORE_BIN_COMMIT = 'b83a174e95996e19826edc9e0498323e40bf7a63'
XRAY_VERSION = 'v26.10.21'
DEPS = {
    'osx-arm64': ('macos-arm64', 'macos-arm64-v8a', '926cc55fda2a8757dabe4f22dc98772f218ace025f101bd0b68aee232e59d5dc'),
    'osx-x64': ('macos-64', 'macos-64', '8e5169b429e76ce5f550c8294db465bc259f30c158ba900aa40802b76ad2f66e'),
    'win-x64': ('windows-64', 'windows-64', 'fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827'),
    'win-arm64': ('windows-arm64', 'windows-arm64-v8a', 'bb44af3380c9975f951ce7645c04d56ab600040e68f23974a2806e08e0a3f872'),
}
ROOT = Path(__file__).resolve().parents[1]


def fetch(url, path):
    request = urllib.request.Request(url, headers={'User-Agent': 'v2rayN-WARP-release'})
    with urllib.request.urlopen(request, timeout=120) as response, path.open('wb') as dest:
        shutil.copyfileobj(response, dest)


def extract(archive, destination):
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            path = destination / item.filename
            assert path.resolve().is_relative_to(destination.resolve()), 'Unsafe ZIP member'
        z.extractall(destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rid', choices=DEPS, required=True)
    parser.add_argument('--publish-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    publish = args.publish_dir.resolve()
    # Publishing directories must contain only compiled program output.
    assert not any(p.name.startswith(('guiConfigs', 'guiLogs', 'guiTemps', 'personal-data')) or
                   p.name.endswith('.private.json') for p in publish.rglob('*')), 'Private data in publish output'
    label, xray_asset, digest = DEPS[args.rid]
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve() / ('v2rayN-WARP-' + RID_LABELS[args.rid] + '.zip')
    with tempfile.TemporaryDirectory(prefix='warp-release-') as temp:
        work = Path(temp)
        base_zip, xray_zip = work / 'cores.zip', work / 'xray.zip'
        fetch(f'https://raw.githubusercontent.com/2dust/v2rayN-core-bin/{CORE_BIN_COMMIT}/v2rayN-{label}.zip', base_zip)
        fetch(f'https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/Xray-{xray_asset}.zip', xray_zip)
        assert hashlib.sha256(xray_zip.read_bytes()).hexdigest() == digest, 'Xray checksum mismatch'
        extract(base_zip, work / 'cores')
        extract(xray_zip, work / 'xray')
        bins = [p for p in (work / 'cores').rglob('bin') if (p / 'xray').is_dir()]
        assert len(bins) == 1, 'Unexpected official core bundle layout'
        bin_dir = bins[0]
        exe = 'xray.exe' if args.rid.startswith('win-') else 'xray'
        xray = work / 'xray' / exe
        assert xray.is_file()
        xray.chmod(0o755)
        info = {'tag': os.environ.get('GITHUB_REF_NAME'), 'commit': os.environ.get('GITHUB_SHA'),
                'rid': args.rid, 'xray': XRAY_VERSION, 'coreBinCommit': CORE_BIN_COMMIT}
        if args.rid.startswith('osx-'):
            # ZIP extraction drops Unix modes. Restore native core executable permissions.
            for p in bin_dir.rglob('*'):
                if p.is_file():
                    with p.open('rb') as binary:
                        magic = binary.read(4)
                    if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
                        p.chmod(0o755)
            app = work / 'v2rayN WARP.app'
            subprocess.run([sys.executable, str(ROOT / 'package-personal-macos.py'),
                            '--publish-dir', str(publish), '--core-bin-dir', str(bin_dir),
                            '--xray', str(xray), '--output', str(app)], check=True)
            # Metadata stays outside the signed app bundle.
            staging = work / 'macos-package'
            staging.mkdir()
            shutil.move(str(app), staging / app.name)
            (staging / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2))
            subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent',
                            str(staging), str(output)], check=True)
        else:
            staging = work / 'v2rayN WARP'
            shutil.copytree(publish, staging)
            shutil.copytree(bin_dir, staging / 'bin', dirs_exist_ok=True)
            shutil.copy2(xray, staging / 'bin/xray/xray.exe')
            shutil.copy2(ROOT / 'LICENSE', staging / 'LICENSE-v2rayN.txt')
            (staging / 'NotStoreConfigHere.txt').write_text('Use the separate v2rayN-WARP application data directory.\n')
            (staging / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2))
            shutil.make_archive(str(output.with_suffix('')), 'zip', staging.parent, staging.name)
    output.with_suffix('.zip.sha256').write_text(hashlib.sha256(output.read_bytes()).hexdigest() + '  ' + output.name + '\n')
    print(output)


if __name__ == '__main__':
    main()
