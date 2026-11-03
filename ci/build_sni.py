"""Build the pinned native SNI helper and package its matching dependencies."""
import argparse
import hashlib
import io
import pathlib
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = {
    'osx-arm64': 'aarch64-apple-darwin',
    'osx-x64': 'x86_64-apple-darwin',
    'win-x64': 'x86_64-pc-windows-gnu',
}
WINDIVERT_SHA256 = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
BINDINGS = {
    ('windivert', '0.7.0-beta.4'): '4bbb7dcc054cce9781ee0d258fa4115182bdc3fc8706350476d4ce96206daed9',
    ('windivert-sys', '0.11.0-beta.2'): '2eace207a00d158e8340b0f9217f1f7e379eaedf364a21edb92109f0e8eb0778',
}


def download(url, digest=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'v2rayN-SNI-build'})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read()
    if digest and hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('Dependency checksum mismatch: ' + url)
    return data


def windows_dependencies(output):
    archive = download('https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip', WINDIVERT_SHA256)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for name in ('WinDivert.dll', 'WinDivert64.sys'):
            member = next(n for n in z.namelist() if n.endswith('/x64/' + name))
            (output / name).write_bytes(z.read(member))
        licenses = [n for n in z.namelist() if n.rsplit('/', 1)[-1].startswith(('LICENSE', 'COPYING'))]
        if not licenses:
            raise RuntimeError('Missing WinDivert license')
        for index, member in enumerate(licenses):
            (output / f'LICENSE-WinDivert-{index}.txt').write_bytes(z.read(member))
    (output / 'WinDivert-source-v2.2.2.zip').write_bytes(download('https://github.com/basil00/WinDivert/archive/refs/tags/v2.2.2.zip'))
    # The statically linked LGPL Rust bindings accompany the complete helper
    # source and build scripts so recipients can rebuild/relink the helper.
    for (name, version), digest in BINDINGS.items():
        archive = download(f'https://static.crates.io/crates/{name}/{name}-{version}.crate', digest)
        (output / f'{name}-{version}.crate').write_bytes(archive)
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
            for item in tar:
                if item.isfile() and item.name.rsplit('/', 1)[-1].startswith(('LICENSE', 'COPYING')):
                    (output / f'{name}-{item.name.rsplit("/", 1)[-1]}').write_bytes(tar.extractfile(item).read())
    (output / 'WINDOWS-NOTICES.txt').write_text(
        'WinDivert and its Rust bindings are LGPL-3.0-or-later.\n'
        'The signed driver, upstream source archives, binding crate sources,\n'
        'complete helper source, Cargo.lock and build script accompany this build.\n'
        'The original SNI spoofing source and local adapter are MIT licensed.\n'
        'To rebuild/relink: unpack sni-helper-source.zip and run\n'
        'cargo build --locked --release --bin sni-spoof-helper --target x86_64-pc-windows-gnu\n'
        'with Rust and MinGW GCC installed; keep WinDivert64.sys beside the executable.\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rid', choices=TARGETS, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    source = ROOT / 'third_party/sni-spoofing-rust'
    target = TARGETS[args.rid]
    exe = 'sni-spoof-helper' + ('.exe' if args.rid.startswith('win') else '')
    subprocess.run(['cargo', 'build', '--manifest-path', str(source / 'Cargo.toml'),
                    '--locked', '--release', '--bin', 'sni-spoof-helper', '--target', target], check=True)
    args.output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / 'target' / target / 'release' / exe, args.output / exe)
    (args.output / exe).chmod(0o755)
    shutil.copy2(source / 'LICENSE', args.output / 'LICENSE-sni-spoofing.txt')
    shutil.copy2(source / 'UPSTREAM', args.output / 'UPSTREAM.txt')
    with zipfile.ZipFile(args.output / 'sni-helper-source.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for file in sorted(source.rglob('*')):
            rel = file.relative_to(source)
            if file.is_file() and rel.parts[0] not in ('target', '.git'):
                z.write(file, rel)
        z.write(__file__, 'build_sni.py')
    if args.rid == 'win-x64':
        windows_dependencies(args.output)


if __name__ == '__main__':
    main()
