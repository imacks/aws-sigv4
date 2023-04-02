Code Contributions
==================
All code and documentation contributions are welcome. You can make a contribution via the [Pull Requests](https://github.com/imacks/aws-sigv4/pulls) page. Refer to the guideline below when submitting pull requests.

1. Any code you submit will be released under the license of this project, which is [available here](./LICENSE). For substantial contributions, you may be requested to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement).

2. If you would like to implement support for a significant feature that is not yet available in this project, discuss with the code owners by filing [an issue](https://github.com/imacks/aws-sigv4/issues) first. This will avoid any duplication of effort.

3. All pull requests should contain unit tests as appropriate. Bugfixes should contain unit tests that exercise the corrected behavior (i.e., the test should fail without the bugfix and pass with it), and new features should be accompanied by tests exercising the feature.

4. Pull requests with failing tests will not be merged until the failures are resolved. Pull requests that cause a significant drop in the project's test coverage percentage are unlikely to be merged until sufficient unit tests have been added.

5. All exported members such as functions, methods, variables and constants must be documented. Internal members should be documented unless its name is self-documenting and obvious.

6. Avoid using new packages other than standard Go library packages. Pull requests that introduces new external dependency packages will not likely be accepted. If you discover an issue with a package that this project depends on, create an issue to discuss with the code owners.
