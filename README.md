# Nixpkgs Security Tracker

The **Nixpkgs Security Tracker** is a web service for managing information on vulnerabilities in software distributed through Nixpkgs.

This software is currently in prototype stage.
A demo deployment is available at <https://tracker.security.nixos.org>.

This tool is eventually supposed to be used by the Nixpkgs community to effectively work through security advisories.
We identified three interest groups that the tool is going to address:

**Nix security team members** use this to access an exhaustive feed of CVEs being published, in order to decide on their relevance, link them to affected packages in Nixpkgs, notify package maintainers and discuss the issue with other team members.

**Nixpkgs package maintainers** are able to get notified and receive updates on security issues that affect packages that they maintain.
By discussing issues with security team members and other maintainers, they can further help on figuring out which channels and packages are affected and ultimately work on fixes for the issue.

**Nixpkgs users** are able to subscribe and stay updated on ongoing security issues that affect the packages they use.

## Contributing

Please see the [**Contributing Guide**](CONTRIBUTING.md) for more information on how to get started.

## History

- **2023**

  The prototype was funded through the [Sovereign Tech Fund "Contribute Back Challenge" 2023](https://www.sovereign.tech/news/contribute-back-challenges-participants-selected) investment, after a [successful application](https://discourse.nixos.org/t/nixpkgs-supply-chain-security-project/34345) with a [proposal to strengthen NixOS security infrastructure](https://github.com/nix-community/projects/blob/274c6d15708b8f0f6e0b3f9782e3959e076ff792/proposals/nixpkgs-security.md).

- **2024**

  Production deployment got delayed due to technical and organisational challenges, with slow progress on volunteered time past the original schedule.

  [Remaining work was picked up end of the year](https://discourse.nixos.org/t/nixpkgs-supply-chain-security-project/34345/22), and concluded with a [demo to the NixOS security team](https://discourse.nixos.org/t/nixpkgs-supply-chain-security-project/34345/27).

- **2025**

  Continued development of the Nixpkgs security tracker funded via [Tweag](https://www.tweag.io/), as part of a larger effort to improve robustness of the Nix ecosystem.

  The [NixOS security team](https://nixos.org/community/teams/security/) started productive use, publishing and addressing numerous [security issues](https://github.com/NixOS/nixpkgs/issues?q=is%3Aissue%20state%3Aopen%20label%3A%221.severity%3A%20security%22%20author%3Aapp%2Fnixpkgs-security-tracker).
