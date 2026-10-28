# Dynamic Library Dependencies

This file is the authoritative dynamic-library version manifest for Autobricks
PKI packages. Package builds must select owner-produced artifacts whose
canonical filenames exactly match this manifest. Existing completed packages
are not retrofitted by this file.

| Component | Version | Linux artifact | macOS artifact |
| --- | --- | --- | --- |
| certificate | 1.0.128 | `libautobricks_certificate_1.0.128.so` | `libautobricks_certificate_1.0.128.dylib` |
| comm | 0.2.7 | `libautobricks_comm_0.2.7.so` | `libautobricks_comm_0.2.7.dylib` |
| ipc | 0.2.212 | `libautobricks_ipc_0.2.212.so` | `libautobricks_ipc_0.2.212.dylib` |
| service | 0.2.210 | `libautobricks_service_0.2.210.so` | `libautobricks_service_0.2.210.dylib` |
| transport | 0.1.6 | `libautobricks_transport_0.1.6.so` | `libautobricks_transport_0.1.6.dylib` |

The optional Auth runtime library is not bundled by the PKI package and is not
part of this package manifest.
