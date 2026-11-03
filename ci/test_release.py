import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def run_operation(self, operation):
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/fork',
                        GITHUB_REF_NAME='v1.0.0', GITHUB_REF_TYPE='tag'), patch('sys.argv', ['release.py', operation]):
            release.main()

    def test_published_release_is_never_overwritten(self):
        with patch.object(release.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"isDraft":false}')):
            with self.assertRaises(AssertionError):
                self.run_operation('begin')

    def test_missing_asset_keeps_release_as_draft(self):
        assets = [{'name': name, 'size': 100} for name in sorted(release.EXPECTED)[1:]]
        with patch.object(release, 'gh', return_value=json.dumps(dict(isDraft=True, assets=assets))) as gh:
            with self.assertRaises(AssertionError):
                self.run_operation('finish')
            self.assertEqual(gh.call_count, 1)

    def test_complete_release_is_published(self):
        assets = [{'name': name, 'size': 100} for name in release.EXPECTED]
        with patch.object(release, 'gh', return_value=json.dumps(dict(isDraft=True, assets=assets))) as gh:
            self.run_operation('finish')
            self.assertIn('--draft=false', gh.call_args.args)

    def test_branch_cannot_publish(self):
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/fork', GITHUB_REF_NAME='main', GITHUB_REF_TYPE='branch'), patch('sys.argv', ['release.py', 'begin']), patch.object(release, 'gh') as gh:
            with self.assertRaises(AssertionError):
                release.main()
            gh.assert_not_called()

    def test_rerunning_a_build_cannot_replace_published_assets(self):
        with patch.object(release, 'gh', return_value='{"isDraft":false}') as gh:
            with self.assertRaises(AssertionError):
                self.run_operation('upload')
            self.assertEqual(gh.call_count, 1)


if __name__ == '__main__':
    unittest.main()
