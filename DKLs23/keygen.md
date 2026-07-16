# Threshold (i.e.,  $t$-out-of-$n$) relaxed distributed key generation

## Input

- Number of signers $n \ge 2$
- Party index $i$, $0 \le i \lt n$
- Threshold parameter $t$, $2 \le t \lt n$
- Context id $\mathsf{sid}$
- Curve $\mathbb{E}$ with generator $G$ of prime order $q$

## Round 1: commit

Party $i$:
- Sample $s_{i,0}, s_{i,1}, \cdots, s_{i,t-1} \leftarrow \mathbb{Z}_q^t$ as coefficients of degree-(t-1) polynomial $p_i$
- Compute $n$ subshares for $[n]$ as $p_i(1), p_i(2), \cdots, p_i(n)$
- Compute $t$ subshare curve points for $[0, t-1]$ as $P_i(0) = p_i(0)\cdot G, P_i(1) = p_1(0)\cdot G, \cdots, P_i(t-1) = p_i(t-1)\cdot G$
- Broadcast commit subshare curve points:
    - Context $\text{ctx}$: Commiter $i$, receivers $[n] \setminus \{i\}$, $\mathsf{sid}$
    - Compute $(V, m, u)_i \leftarrow \text{Commit}(\text{ctx}, \text{subshare curve points})$
    - Send $(\mathsf{NCommit}, \mathsf{sid}, V_i)$ to every other parties
- 2-party commit subshares
    - For $j \in [n]\setminus\{i\}$
        - Context $\text{ctx}'$: Committer $i$, receiver $j$, $\mathsf{sid}$:
        - $(V', m', u')_i \leftarrow \text{Commit}(\text{ctx}, p_i(j))$
        - Send $(\mathsf{2Commit}, \mathsf{sid}, V'_i)$ to party $P_j$

## Round 2: decommit

Party $i$:
- Receive all broadcast commitments $\{V_j: j \neq i\}$ and 2-party commitments $\{V'_j: j \neq i\}$
- Echo for broadcast commitments:
    - Compute echo digest $h_i = H(\mathsf{sid}, V_1, \cdots, V_n)
    - Send $(\mathsf{NEcho}, \mathsf{sid}, h_i)$ to every other party
- Open for broadcast commitments and 2-party commitments
    - Send $(\mathsf{NOpen}, \mathsf{sid}, m_i, u_i)$ to every other party
    - Send $(\mathsf{2Open}, \mathsf{sid}, m'_i, u'_i)$ to every other party

## Round 3: verify

Party $i$:
- Receive all $\{h_j, m_j, u_j, m'_j, u'_j: j\neq i\}$
- Echo agreement for broadcast commitments:
    - Abort if exists $h_j \neq h_i$
- Binding
    - For $j \in [n]\setminus \{i\}$:
        - Abort if broadcast commitment not: $\text{Verify}(\text{ctx}, V_j, m_j, u_j)$
        - Abort if 2-party commitment not: $\text{Verify}(\text{ctx}', V'_j, m'_j, u'_j)$
- Sum to $t$ share curve points for $k \in [0, t-1]: $P(k) = P_0(k) + P_1(k) + \cdots P_n(k)$
- Sum to share: $p(i) = p_1(i) + p_2(i) + \cdots + p_n(i)$
- Compute share curve point $P_i = p(i) \cdot G$
- Compute expected share curve point $Q$:
    - If $i \in [t-1]$:
        - $Q \leftarrow P(i)$
    - Else build from lagrange $t$ curve points:
        - Form $t$ indexes: $S = [t-1] \cup \{i\}$
        - Let $\lambda_k \leftarrow \mathsf{lagrange}(S, k, 0) \in Z_q$
        - $Q \leftarrow \lambda_i^{-1} \cdot (P(0) - (\lambda_1 \cdot P(1) + \lambda_2 \cdot P(2) + \cdots + \lambda_{t-1} P(t-1)))$
- Abort if $P_i \neq Q$
- Output context id $\mathsf{sid}$, public key $pk = P(0)$, share $p(i)$
