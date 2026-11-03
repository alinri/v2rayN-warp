"""Release assets are the only inter-job storage. No Actions Artifacts/cache."""
import json
import os
from pathlib import Path
import subprocess
import sys

RID_LABELS = {'osx-arm64': 'macos-arm64', 'osx-x64': 'macos-x64',
              'win-x64': 'windows-x64', 'win-arm64': 'windows-arm64'}
EXPECTED = {f'v2rayN-WARP-{label}.zip{suffix}'
            for label in RID_LABELS.values() for suffix in ('', '.sha256')}


def gh(*args, capture=False):
    return subprocess.run(['gh', *args], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def main():
    repo, tag = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_REF_NAME']
    assert os.environ['GITHUB_REF_TYPE'] == 'tag', 'Publishing requires an existing tag'
    base = ['--repo', repo]
    command = sys.argv[1]
    if command == 'begin':
        view = subprocess.run(['gh', 'release', 'view', tag, *base, '--json', 'isDraft'],
                              capture_output=True, text=True)
        if view.returncode == 0:
            assert json.loads(view.stdout)['isDraft'], 'Refusing to overwrite an already published release'
        else:
            gh('release', 'create', tag, *base, '--verify-tag', '--draft',
               '--title', 'v2rayN WARP ' + tag, '--generate-notes')
    elif command == 'upload':
        info = json.loads(gh('release', 'view', tag, *base, '--json', 'isDraft', capture=True))
        assert info['isDraft'], 'Refusing to upload into an already published release'
        files = sorted(Path('dist/release').glob('*'))
        assert len(files) == 2 and {p.name for p in files}.issubset(EXPECTED)
        gh('release', 'upload', tag, *base, '--clobber', *(str(p) for p in files))
    elif command == 'finish':
        info = json.loads(gh('release', 'view', tag, *base, '--json', 'assets,isDraft', capture=True))
        assert info['isDraft'], 'Release must remain a draft until every build passes'
        assets = {x['name']: x['size'] for x in info['assets']}
        assert EXPECTED == set(assets) and all(assets.values()), 'Incomplete release; keeping draft'
        prerelease = 'true' if '-' in tag else 'false'
        gh('release', 'edit', tag, *base, '--draft=false', '--prerelease=' + prerelease)
    else:
        raise ValueError('Unknown release operation')


if __name__ == '__main__':
    main()
