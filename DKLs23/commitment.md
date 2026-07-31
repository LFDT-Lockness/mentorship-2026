# Commitment functionality

The commitment functionality as defined in DKLs23 Section 3.3 and 7.1.

## Parameters

- SHA-256 $H$
- Security parameter $\lambda = 128$
- [Unambiguous encoding](encoding.md) $\mathsf{Encode}$

## Commit

$\text{Commit}()\rightarrow (V, m, u)$

Input
- Context
    - Committer id $S$
    - Receiver id $R$
    - Context id $\mathsf{sid}$
- Value $m$

Output: commitment $V$ and opening parameter $m, u$
- Sample nonce $u \leftarrow {0,1}^{2\lambda}$
- $V = H(\mathsf{Encode}(S, R, \mathsf{sid}, m, u))$

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
- Return true if $V = H(\mathsf{Encode}(S, R, sid, m, u))$ else false


## Echo digest

$\text{EchoDigest}()\rightarrow V$

Input
- Context id $\mathsf{sid}$
- Commitments $V_1, \cdots, V_n$

Output: echo digest $V$
- $V = H(\mathsf{Encode}(V_1, \cdots, V_n))$

## Echo agreement

$\text{EchoAgree}()\rightarrow \text{true if agreed else false}$

Input
- Echo digest $V$
- Expected digest $V^\prime$

Output
- Return true if $V = V^\prime$ else false

