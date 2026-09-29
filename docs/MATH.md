# Mathematical Specification of AURA (aMHF)

This document specifies the hardened mathematical model of **AURA (Asymmetric Unkeyed-Resistant Algorithm)**, covering the hybrid memory Directed Acyclic Graph (DAG), 2-dimensional block permutation algebra, non-uniform quadratic indexing (TMTO defense), and the asymmetric trapdoor shortcut mechanism.

---

## 1. Parameters & Memory Arena

Let:
* $M$: Total memory cost in Kilobytes ($M \ge 8$).
* $B = 1024$ bytes: Size of one block ($256$ words of $32$-bit integers $\mathbb{Z}_{2^{32}}$).
* $p$: Parallelism degree (number of independent memory lanes, $p \ge 1$).
* $N = \lfloor M / p \rfloor$: Number of blocks per lane.
* $T$: Time cost (number of passes over the memory matrix, $T \ge 1$).
* $\mathcal{M}[l, i]$: The $i$-th block in lane $l$ ($l \in [0, p-1]$, $i \in [0, N-1]$).

---

## 2. Initial Seed Extraction ($H_0$)

Given password $P$, salt $S$, and parameters $(M, T, p, \text{mode}, L_{\text{out}})$:
$$H_0 = \text{SHA-512}\Big( M \parallel T \parallel p \parallel \text{mode} \parallel L_{\text{out}} \parallel P \parallel S \Big)$$

Initial blocks $\mathcal{M}[l, 0]$ and $\mathcal{M}[l, 1]$ are expanded from $H_0$:
$$\mathcal{M}[l, k] = \text{Expand}_{1024}\big( H_0 \parallel l \parallel k \big) \quad \text{for } k \in \{0, 1\}$$

---

## 3. 2-Dimensional Block Permutation ($P$)

Each block $\mathcal{B} \in \mathbb{Z}_{2^{32}}^{256}$ is permuted across both rows and columns using 32-bit Add-Rotate-XOR (ARX) quarter-rounds to defeat divide-and-conquer / bit-slice ASIC attacks:

### 3.1 32-bit ARX Quarter-Round ($G(a, b, c, d)$)
$$\begin{aligned}
a &\leftarrow (a + b) \bmod 2^{32}, & d &\leftarrow (d \oplus a) \lll 16 \\
c &\leftarrow (c + d) \bmod 2^{32}, & b &\leftarrow (b \oplus c) \lll 12 \\
a &\leftarrow (a + b) \bmod 2^{32}, & d &\leftarrow (d \oplus a) \lll 8 \\
c &\leftarrow (c + d) \bmod 2^{32}, & b &\leftarrow (b \oplus c) \lll 7
\end{aligned}$$

### 3.2 2D Block Diffusion Pipeline
1. **Row Permutation**: Permutes each of the sixteen 16-word (64-byte) sub-blocks with column and diagonal quarter-rounds.
2. **Column Stride Permutation**: Permutes across 64-word strides:
   $$G\big(\mathcal{B}[i], \mathcal{B}[i+64], \mathcal{B}[i+128], \mathcal{B}[i+192]\big) \quad \text{for } i \in [0, 63]$$
3. **Cross-Diagonal Permutation**: Inter-weaves non-adjacent chunks across the entire 1024-byte block.

### 3.3 Block Combination Function
Given previous block $\mathcal{B}_{\text{prev}}$ and reference block $\mathcal{B}_{\text{ref}}$:
$$\mathcal{B}_{\text{out}} = \text{Permute}_{2D}\big( \mathcal{B}_{\text{prev}} \oplus \mathcal{B}_{\text{ref}} \big) \oplus \mathcal{B}_{\text{prev}}$$

---

## 4. Non-Uniform Quadratic Reference Indexing (TMTO Defense)

For block $\mathcal{M}[l, i]$ at pass $t$, a pseudo-random value $J \in \mathbb{Z}_{2^{32}}$ is extracted:

1. **Phase 1: Data-Independent (Side-Channel Immune)**
   Used when $\text{mode} = \text{independent}$ or ($\text{mode} = \text{hybrid}$, $t = 0$, and $i < N/2$):
   $$J_{\text{indep}} = \text{ARX-Expand}(t, l, i, M)[i \bmod 256]$$
2. **Phase 2: Data-Dependent (GPU / ASIC Resistant)**
   Used when $\text{mode} = \text{dependent}$ or ($\text{mode} = \text{hybrid}$, and ($t > 0$ or $i \ge N/2$)):
   $$J_{\text{dep}} = \mathcal{M}[l, i-1][0]$$

### 4.1 Quadratic Window Biasing
To defeat Time-Memory Trade-Off (TMTO) graph-pebbling shortcuts:
$$x = \lfloor (J \cdot J) / 2^{32} \rfloor \bmod 2^{32}$$
$$y = \lfloor (\text{windowSize} \cdot x) / 2^{32} \rfloor$$
$$\text{offset} = \text{windowSize} - 1 - y$$
$$j = \begin{cases}
\text{offset} & \text{if } t = 0 \\
(i + 1 + \text{offset}) \bmod N & \text{if } t > 0
\end{cases}$$

This creates an exponential bias towards recently computed blocks, making memory eviction in pebbling games mathematically suboptimal for an attacker.

---

## 5. Asymmetric Trapdoor & Vault Masking

Let $K \in \{0, 1\}^{256}$ be a secret key held in a hardware secure enclave or passkey PRF.

### 5.1 Sealing (Setup)
1. Compute memory-hard DAG output:
   $$D = \text{Aura}(P, S, M, T, p)$$
2. Compute secret Trapdoor Token:
   $$T = \text{HMAC-SHA256}(K, P \parallel S)$$
3. Compute Public Anchor:
   $$A = \text{SHA-256}(D \parallel T \parallel S)$$
4. *(Optional Masked Vault Mode)*:
   $$D_{\text{stored}} = D \oplus \text{HKDF-SHA256}(K, S, \text{"aura:vault:mask"})$$

### 5.2 Verification Complexity
* **With Trapdoor Key $K$ (Legitimate User)**:
  Compute $T' = \text{HMAC-SHA256}(K, P \parallel S)$.
  Unmask $D = D_{\text{stored}} \oplus \text{HKDF-SHA256}(K, S)$.
  Check $A \stackrel{?}{=} \text{SHA-256}(D \parallel T' \parallel S)$ in **$O(1)$ operations ($< 0.5\text{ ms}$)**.
* **Without Trapdoor Key $K$ (Offline Attacker)**:
  * In standard mode: Attacker must compute $D' = \text{Aura}(P', S, M, T, p)$ over the full $M$-kilobyte memory DAG ($O(M \cdot T)$ memory bandwidth).
  * In masked vault mode: $D_{\text{stored}}$ is cryptographically blinded under $K$, making offline dictionary confirmation **$100\%$ mathematically impossible without $K$**.
