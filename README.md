# Lockness Mentorship Programs 2026

Two Lockness projects participate in LFX Mentorship Program 2026. This pages describes these projects, defines roadmap, centralizes all other docs.
- [Advanced Threshold Key Management](), mentee: 
- [Implement DKLs23 (threshold ECDSA) protocol](https://mentorship.lfx.linuxfoundation.org/project/0bc24781-b769-4808-8493-4a6066fecb9f), mentee: [@zheguang](https://github.com/zheguang)

## Advanced Threshold Key Management
- LFX Mentorship platform: [link](https://mentorship.lfx.linuxfoundation.org/project/e27c5963-4a4c-4d17-98de-94d66eb8a2d6)
- Mentee: [@Pranavjeet-Naidu](https://github.com/Pranavjeet-Naidu)
- Duration: June 15 – Nov 30

In this project, the mentee builds production-ready lifecycle tooling for threshold keys, implementing three protocols as standalone Rust libraries: key share repair, key refresh, and key reshare. The work happens within the Lockness ecosystem using the `round-based` MPC framework and `generic-ec` library, adapting academic papers like CGGMP24. [See full description](https://mentorship.lfx.linuxfoundation.org/project/e27c5963-4a4c-4d17-98de-94d66eb8a2d6).

### Roadmap

| Objective | Description | Output | Est. time |
|---|---|---|---|
| Key refresh spec (non-threshold) | Study CGGMP24 (Fig. 7) and write a specification for the non-threshold key refresh protocol | Spec | 2 weeks |
| Key refresh implementation (non-threshold) | Implement the protocol from the spec | Crate | 3 weeks |
| Key refresh spec (threshold) | Modify the protocol to support a t-out-of-n threshold setting and write the spec | Spec | 2 weeks |
| Key refresh implementation (threshold) | Implement the threshold variant | Crate | 3 weeks |
| Mid-Term evaluation | — | — | Aug 24–31 |
| Key repair research | Dive into secret-sharing constructions to determine how t parties can restore a lost share | Research notes | 1 week |
| Key repair implementation | Implement the share-repair protocol | Crate | 2 weeks |
| Key reshare research | Survey existing reshare constructions, comparing communication complexity, security trade-offs, and efficiency | Comparison doc | 3 weeks |
| Key reshare spec | Write the spec for the chosen protocol | Spec | 3 weeks |
| Key reshare implementation | Implement the protocol | Crate | 3 weeks |
| Final evaluation | — | — | Nov 16–30 |

