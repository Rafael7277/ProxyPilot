import json
import pathlib
import sys
import unittest
from urllib.error import HTTPError
from unittest.mock import MagicMock, patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from proxypilot_app import updates


class UpdateCheckTests(unittest.TestCase):
    def test_project_repository_is_used_by_default(self):
        response={"tag_name":"v1.0.0","html_url":"https://github.com/Rafael7277/ProxyPilot/releases/tag/v1.0.0",
                  "published_at":"2026-11-01T10:00:00Z","body":"Initial release","assets":[]}
        context=MagicMock();context.__enter__.return_value.read.return_value=json.dumps(response).encode()
        with patch.dict('os.environ',{},clear=True),patch.object(updates,'urlopen',return_value=context) as open_url:
            result=updates.check(current_version='1.0.0a1')
        self.assertTrue(result['configured'])
        self.assertEqual(result['repository'],'Rafael7277/ProxyPilot')
        self.assertEqual(result['latest_version'],'1.0.0')
        open_url.assert_called_once()

    def test_invalid_repository_is_rejected_before_network_access(self):
        with patch.object(updates,'urlopen') as open_url:
            result=updates.check('../owner',current_version='1.0.0')
        self.assertIn('owner/name',result['message'])
        open_url.assert_not_called()

    def test_latest_stable_release_and_supported_archive_are_reported(self):
        response={"tag_name":"v1.1.0","html_url":"https://github.com/acme/proxypilot/releases/tag/v1.1.0",
                  "published_at":"2026-11-01T10:00:00Z","body":"New stable version",
                  "assets":[{"name":"proxypilot-1.1.0-source.tar.gz",
                             "browser_download_url":"https://github.com/acme/proxypilot/releases/download/v1.1.0/proxypilot-1.1.0-source.tar.gz",
                             "size":100}]}
        context=MagicMock();context.__enter__.return_value.read.return_value=json.dumps(response).encode()
        with patch.object(updates,'urlopen',return_value=context) as open_url:
            result=updates.check('acme/proxypilot',current_version='1.0.0a1')
        self.assertTrue(result['update_available'])
        self.assertTrue(result['compatible'])
        self.assertEqual(result['latest_version'],'1.1.0')
        self.assertEqual(result['integrity_model'],'not checked; release metadata only')
        open_url.assert_called_once()

    def test_prerelease_order_is_semver_aware(self):
        self.assertTrue(updates._is_newer('1.0.0-beta.1','1.0.0-alpha.2'))
        self.assertFalse(updates._is_newer('1.0.0-alpha.2','1.0.0-beta.1'))
        self.assertTrue(updates._is_newer('1.0.0','1.0.0rc2'))

    def test_alpha_build_falls_back_to_latest_published_release(self):
        from io import BytesIO
        release={"tag_name":"v1.0.0-alpha.2","html_url":"https://github.com/acme/proxypilot/releases/tag/v1.0.0-alpha.2",
                 "published_at":"2026-11-14T10:00:00Z","body":"Alpha update","draft":False,"prerelease":True,
                 "assets":[{"name":"proxypilot-1.0.0-alpha.2-source.tar.gz",
                            "browser_download_url":"https://github.com/acme/proxypilot/releases/download/v1.0.0-alpha.2/proxypilot-1.0.0-alpha.2-source.tar.gz",
                            "size":100}]}
        error=HTTPError("https://api.github.com/repos/acme/proxypilot/releases/latest",404,"Not Found",{},BytesIO())
        context=MagicMock();context.__enter__.return_value.read.return_value=json.dumps([release]).encode()
        with patch.object(updates,'urlopen',side_effect=[error,context]) as open_url:
            result=updates.check('acme/proxypilot',current_version='1.0.0a1')
        self.assertTrue(result['update_available'])
        self.assertTrue(result['compatible'])
        self.assertEqual(result['latest_version'],'1.0.0-alpha.2')
        self.assertEqual(open_url.call_count,2)


if __name__=='__main__':unittest.main()
