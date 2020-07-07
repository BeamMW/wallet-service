## Beam Wallet Service

This is the beam wallet service. It allows to implement lightweight wallets using BEAM API.
Check out the [Wallet Service docs](https://github.com/BeamMW/beam/wiki/Wallet-Service).

## How to build

Wallet service and related projects are supposed to be run on Linux only. It is possible to build everything for Windows and using Windows but it is not oficially supported. Releases are also provided only for Linux.

1. Install required tools to build the generic BEAM project. Refer [BEAM build instructions](https://github.com/BeamMW/beam/wiki/How-to-build) for detals. For example if you're using Ubuntu 18.04 Desktop you need to execute steps 1. Install dependencies & 2.Install cmake from the 'Ubuntu 18.04 Desktop' section.

2. Install golang. You need at least v1.13.0 to build the project. If the relevant package is provided with your OS it is better to use it. For example `sudo dnf install golang` on Fedora. If your OS doesn't not provide recent golang packages (like Ubuntu 18.04) use instructions [from the official website](https://golang.org/doc/install)
