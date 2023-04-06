# NeuVector

NeuVector vulnerability scanner for the SUSE NeuVector Container Security Platform.

The scanner has multiple working modes.

The scanner runs with the NeuVector controller to provide registry scan and runtime scan functions. Please see the [document](https://open-docs.neuvector.com) and the [helm chart](https://github.com/neuvector/neuvector-helm) of how to deploy scanners in this mode.

The scanner runs in standalone mode, print the scan results to the screen and save it to the file at the same time. Run the scanner in the standalone mode with the following command.

```
docker run --rm  neuvector/scanner -i ubuntu:18.04
```

The scanner can also be used in the CI/CD pipeline though various of plugins.

Note: Deploying from the Rancher Manager 2.6.5+ NeuVector chart pulls from the rancher-mirrored repo and deploys into the cattle-neuvector-system namespace.

# Bugs & Issues
Please submit bugs and issues to [neuvector/neuvector](//github.com/neuvector/neuvector/issues) with a title starting with `[SCAN] `.

Or just [click here](//github.com/neuvector/neuvector/issues/new?title=%5BSCAN%5D%20) to create a new issue.

# License

Copyright © 2016-2022 [NeuVector Inc](https://neuvector.com). All Rights Reserved

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

