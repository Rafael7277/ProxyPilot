import importlib.util
import pathlib
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

    def test_stable_release_versions_are_unchanged(self):
        self.assertEqual(build_release._to_python_version("1.2.3"),"1.2.3")
        self.assertEqual(build_release._to_release_version("1.2.3"),"1.2.3")
        self.assertEqual(build_release._to_debian_version("1.2.3"),"1.2.3")

    def test_only_supported_semver_release_labels_are_accepted(self):
        for value in ("1.0", "1.0.0-dev.1", "1.0.0-foo.1", "v1.0.0"):
            with self.subTest(value=value),self.assertRaises(ValueError):
                build_release._to_python_version(value)


if __name__=="__main__":unittest.main()
