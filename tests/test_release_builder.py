import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("build_release",ROOT/"scripts/build_release.py")
build_release=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_release)


class ReleaseVersionTests(unittest.TestCase):
    def test_semver_alpha_maps_to_python_and_debian_versions(self):
        self.assertEqual(build_release._to_python_version("1.0.0-alpha.1"),"1.0.0a1")
        self.assertEqual(build_release._to_release_version("1.0.0a1"),"1.0.0-alpha.1")
        self.assertEqual(build_release._to_debian_version("1.0.0-alpha.1"),"1.0.0~alpha1")
        self.assertEqual(build_release._debian_artifact_name("1.0.0-alpha.1","amd64"),
                         "proxypilot_1.0.0-alpha.1_amd64.deb")

    def test_project_version_is_the_semver_source_for_release_builds(self):
        release_version = build_release.version()
        self.assertRegex(release_version, r"^\d+\.\d+\.\d+-(?:alpha|beta|rc)\.\d+$")
        self.assertEqual(build_release._to_release_version(release_version), release_version)
        self.assertRegex(build_release._to_python_version(release_version),
                         r"^\d+\.\d+\.\d+(?:a|b|rc)\d+$")

    def test_stable_release_versions_are_unchanged(self):
        self.assertEqual(build_release._to_python_version("1.2.3"),"1.2.3")
        self.assertEqual(build_release._to_release_version("1.2.3"),"1.2.3")
        self.assertEqual(build_release._to_debian_version("1.2.3"),"1.2.3")

    def test_only_supported_semver_release_labels_are_accepted(self):
        for value in ("1.0", "1.0.0-dev.1", "1.0.0-foo.1", "v1.0.0"):
            with self.subTest(value=value),self.assertRaises(ValueError):
                build_release._to_python_version(value)

    def test_debian_package_declares_ssh_and_embedded_terminal_runtime(self):
        if not shutil.which("dpkg-deb"):
            self.skipTest("dpkg-deb is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            deb = build_release._make_deb(pathlib.Path(tmp), "1.0.0-alpha.99", "amd64",
                                          "ProxyPilot test <noreply@example.test>")
            control = subprocess.run(["dpkg-deb", "--field", str(deb), "Depends"],
                                     capture_output=True, text=True, check=True).stdout
            self.assertIn("python3-paramiko", control)
            self.assertIn("gir1.2-vte-3.91", control)
            extracted = pathlib.Path(tmp) / "payload"
            extracted.mkdir()
            subprocess.run(["dpkg-deb", "--extract", str(deb), str(extracted)],
                           capture_output=True, check=True)
            self.assertTrue((extracted / "usr/lib/proxypilot/src/proxypilot_app/remote_access.py").is_file())
            self.assertTrue((extracted / "usr/lib/proxypilot/src/proxypilot_app/remote_ui.py").is_file())


if __name__=="__main__":unittest.main()
