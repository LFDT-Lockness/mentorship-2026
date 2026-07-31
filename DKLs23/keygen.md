# Threshold (i.e.,  $t$-out-of-$n$) relaxed distributed key generation

## Functions
- [Commitment](commitment.md) $\mathsf{Commit}$, $\mathsf{Verify}$
- [Echo agreement](commitment.md) $\mathsf{EchoDigest}$, $\mathsf{EchoAgree}$

## Input

- Number of signers $n \ge 2$
- Party index $i$, $1 \le i \le n$
- Threshold parameter $t$, $2 \le t \lt n$
- Context id $\mathsf{sid}$
- Curve $\mathbb{E}$ with generator $G$ of prime order $q$

## Round 1: commit

Party $i$:
- Sample $s_{i,0}, s_{i,1}, \cdots, s_{i,t-1} \leftarrow \mathbb{Z}_q^t$ as coefficients of degree-$(t-1)$ polynomial $p_i$
- Compute $n$ subshares for $[n]$ as $p_i(1), p_i(2), \cdots, p_i(n)$
- Compute $t$ subshare curve points for $[0, t-1]$ as $\overrightarrow{P}_i = (P_i(0), P_i(1),\cdots, P_i(t-1))$ where  $P_i(j) = p_i(j)\cdot G$
- Broadcast commit subshare curve points:
    - With $\mathsf{ctx}$: Commiter $i$, receivers $[n] \setminus \{i\}$, context id $\mathsf{sid}$:
        - Compute $(V_i, m_i, u_i) \leftarrow \text{Commit}(\mathsf{ctx}, \overrightarrow{P}_i)$
        - Send $(\mathsf{NCommit}, \mathsf{sid}, V_i)$ to every other parties
- 2-party commit subshares
    - For $j \in [n]\setminus\{i\}$
        - With context $\mathsf{ctx}^\prime$: Committer $i$, receiver $j$, context id $\mathsf{sid}$:
            - $(V^\prime_i, m^\prime_i, u^\prime_i) \leftarrow \text{Commit}(\mathsf{ctx}, p_i(j))$
            - Send $(\mathsf{2Commit}, \mathsf{sid}, V^\prime_i)$ to party $j$

## Round 2: decommit

Party $i$:
- Receive all broadcast commitments $\{V_j: j \neq i\}$ and 2-party commitments $\{V^\prime_j: j \neq i\}$
- Echo for broadcast commitments:
    - Compute echo digest $h_i = \mathsf{EchoDigest}(\mathsf{sid}, V_1, \cdots, V_n)$
    - Send $(\mathsf{NEcho}, \mathsf{sid}, h_i)$ to every other party
- Open for broadcast commitments and 2-party commitments
    - Send $(\mathsf{NOpen}, \mathsf{sid}, m_i, u_i)$ to every other party
    - Send $(\mathsf{2Open}, \mathsf{sid}, m^\prime_i, u^\prime_i)$ to party $j$

## Round 3: verify

Party $i$:
- Receive $\{h_j, m_j, u_j, m^\prime_j, u^\prime_j: j\neq i\}$ from every party $j \neq i$
    - Parse each received $m_j$ as $(P_j(0), P_j(1), \cdots, P_j(t-1))$ from party $j$
    - Parse each received $m^\prime_j$ as $p_j(i)$ from party $j$
- Echo agreement for broadcast commitments:
    - Abort if exists $h_j$ such that $\mathsf{EchoAgree}(h_j, h_i)$ is false: 
        - Send $(\mathsf{Abort}, \mathsf{sid})$ to every other party
        - Go to Output
- Binding
    - For $j \in [n]\setminus \{i\}$:
        - Abort if broadcast commitment $\text{Verify}(\mathsf{ctx}, V_j, m_j, u_j)$ returns false: 
            - Send $(\mathsf{Abort}, \mathsf{sid})$ to every other party
            - Go to Output
        - Abort if 2-party commitment $\text{Verify}(\mathsf{ctx}^\prime, V^\prime_j, m^\prime_j, u^\prime_j)$ returns false
            - Send $(\mathsf{Abort}, \mathsf{sid})$ to every other party
            - Go to next round
- Sum to $t$ share curve points for $k \in [0, t-1]$: $P(k) = P_0(k) + P_1(k) + \cdots P_n(k)$
- Sum to share: $p(i) = p_1(i) + p_2(i) + \cdots + p_n(i)$
- Compute share curve point $P_i = p(i) \cdot G$
- Compute expected share curve point $Q$ as follows:
    - If $i \in [t-1]$:
        - $Q \leftarrow P(i)$
    - Else build from lagrange $t$ curve points:
        - Form $t$ indexes: $S = [t-1] \cup \{i\}$
        - Compute $Q \leftarrow \lambda_i^{-1} \cdot (P(0) - (\lambda_1 \cdot P(1) + \lambda_2 \cdot P(2) + \cdots + \lambda_{t-1} P(t-1)))$ where
            - $\lambda_k := \mathsf{lagrange}(S, k, 0) \in \mathbb{Z}_q$
            - $\mathsf{lagrange}(S, k, x) := \prod_{l\in S, l \neq k} (x-l) \cdot (k-l)^{-1} \in \mathbb{Z}_q$
- Abort if $P_i \neq Q$
    - Send $(\mathsf{Abort}, \mathsf{sid})$ to every other party
    - Go to Output
- Send $(\mathsf{Ok}, \mathsf{sid})$ to every other party

## Output

Party $i$:
- If received $(\mathsf{Abort}, \mathsf{sid})$ from any party, or sent $(\mathsf{Abort}, \mathsf{sid})$ to any party:
    - Output $(\mathsf{Abort}, \mathsf{sid})$
    - Halt from this session $\mathsf{sid}$
- If sent $(\mathsf{Ok}, \mathsf{sid})$ to every other party, and received $(\mathsf{Ok}, \mathsf{sid})$ from every other party:
    - Output $(\mathsf{KeyPair}, \mathsf{sid}, P(0), p(i))$
