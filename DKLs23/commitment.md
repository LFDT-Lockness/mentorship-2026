# Commitment functionality

The commitment functionality as defined in DKLs23 Section 3.3 and 7.1.

## Parameters

- SHA-256 $H$
- Security parameter $\lambda = 256$

## Commit

$\text{Commit}()\rightarrow (V, m, u)$

Input
- Context
    - Committer id $S$
    - Receiver id $R$
    - Context id $\mathsf{sid}$
- Value $m$

Output: commitment $V$ and opening parameter $m, u$
- Sample nonce $u \leftarrow {0,1}^\lambda$
- $V = H(S \parallel R \parallel \mathsf{sid} \parallel m \parallel u)$

## Verify

$\text{Verify}() \rightarrow \text{true if verified else false}$

Input
- Context
    - Committer id $S$
    - Receiver id $R$
    - Context id $\mathsf{sid}$
- Commitment $V$
- Opening parameters $m, u$

Output:
- Return true if $V = H(S, R, sid, m, u)$ else false

