# dexdo-halo2-kit

Copyright (C) 2026 GOSH TECHNOLOGY LTD.

`dexdo-halo2-kit` is free software: you can redistribute it and/or modify
it under the terms of the **GNU Affero General Public License**, version 3,
as published by the Free Software Foundation. The full license text is in
[LICENSE.md](LICENSE.md).

The kit is distributed in the hope that it will be useful, but **WITHOUT
ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
for more details.

## Why AGPL

This kit contains the halo2 zero-knowledge circuits, the witness export
library, and the prover used by DEX.DO. Cryptographic code that mediates
trust between users and a blockchain has to be auditable: every user who
runs a prover built from this code must be able to verify that no extra
witness extraction, key leakage, or backdoor was inserted downstream.

The AGPL network-use clause is the property that enforces this — any
deployment of a modified version of the kit, even one that is only reached
over the network, must publish its source. A more permissive license (MIT,
Apache 2.0) would allow a closed fork to ship a prover service whose
internals could not be inspected, which directly defeats the trust model
of the circuits this kit defines.

## Runtime context

`dexdo-halo2-kit` is consumed by **DEX.DO**
(<https://github.com/gosh-sh/dexdo>), which itself runs as a plugin to the
**Acki Nacki Block Manager** node software published by
GOSH TECHNOLOGY LTD. The Block Manager is distributed separately under
its own license (the Acki Nacki Node License — a Business Source License
with a two-year change date to GNU AGPL-3.0). Refer to the Block Manager
repository for its current license text and terms.

The AGPL terms of `dexdo-halo2-kit` apply only to this repository's own
source code, builds, deployments, and modifications. They do not extend
to or override the licensing of any separately distributed software
(such as DEX.DO or the Block Manager) that this kit is used together
with.
