# Lockness Mentorship Programs 2026

Two Lockness projects participate in LFX Mentorship Program 2026. This pages describes these projects, defines roadmap, centralizes all other docs.

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

## Threshold ECDSA (DKLS24/26) Implementation
- LFX Mentorship platform: [link](https://mentorship.lfx.linuxfoundation.org/project/0bc24781-b769-4808-8493-4a6066fecb9f)
- Mentee: [@zheguang](https://github.com/zheguang)
- Duration: June 15 – Nov 30

In this project, the mentee builds a production-ready, t-out-of-n threshold ECDSA signature library. The work translates the DKLS24 specification into secure Rust, heavily integrating the 2026 cryptanalytic mitigations by [Asharov26] to patch critical adaptive-input vulnerabilities. The implementation happens within the Lockness ecosystem using the `round-based` MPC framework and `generic-ec` library. 

### Roadmap

| Objective | Description | Output | Est. time |
|---|---|---|---|
| Foundations & Literature Review | Read [DKLS24] and [Asharov26].<br/> Grasp Secret Sharing, OT, and  VOLE. | Research notes | 2 weeks |
| Keygen  | Implement Relaxed Keygen (Protocol 7.1) using `generic-ec`. | Crate | 2 weeks |
| OT & RVOLE Specification | Write detailed specs for Sender-Random OT, SoftSpokenOT, and RVOLE. <br/>Explicitly define the architectural choice between Variant II and Variant III of [Asharov26]. | Spec | 2 weeks |
| Base OT & SoftSpokenOT Implementation | Build the foundation OT and OT extension using the `round-based` framework. | Crate | 4-6 weeks |
| Mid-Term evaluation | — | — | Aug 24–31 |
| Random Vector OLE (RVOLE) Implementation | Implement the RVOLE engine.  | Crate | 3-4 weeks |
| Threshold Signing Specification | Map the t-out-of-n state machine for signing from [DKLS24]. | Spec | 2 weeks |
| Threshold Signing Implementation | Implement Rounds 1, 2, and 3. Assemble the final signature scalar securely. | Crate | 2-3 weeks |
| Integration & E2E Testing | Build an integration harness combining keygen and signing over a simulated network loopback. Test adversarial edge cases and invalid consistency checks. | Test suite | 3 weeks |
| Final evaluation | — | — | Nov 16–30 |
