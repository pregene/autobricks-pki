# Checking a source build and installation

Run the build checks from the repository root:

```sh
./scripts/check/panic-gate.sh
```

This checks formatting, compiles with Clippy and runs the regression suite. Compiling commands allocate versions through the common build runner. Isolated checks use temporary fixtures and do not install packages or modify the production WORM mount.

After installing the server and client, run:

```sh
./tests/post-test.sh
```

The command prints installed binary versions and numbered PASS/FAIL/SKIP results. Installed checks query the service and download public trust material; they do not issue or revoke certificates. Checks labelled `Isolated` use local build artifacts and do not verify the installed service.

Build the regression executables with the gate before running this command. Missing or outdated executables produce FAIL; the script does not compile automatically. An optional version argument checks the installed CLI version:

```sh
./tests/post-test.sh <expected-version>
```

These are functional regression checks, not throughput measurements.

[Building packages](../PACKAGE.md) · [Installation](../INSTALL.md)
