# Mathematical Specification of AURA (aMHF)

This document specifies the hardened mathematical model of **AURA (Asymmetric Unkeyed-Resistant Algorithm)**, covering the hybrid memory Directed Acyclic Graph (DAG), 2-dimensional block permutation algebra, non-uniform quadratic indexing (TMTO defense), and the asymmetric trapdoor shortcut mechanism.

---

## 1. Parameters & Memory Arena

Let:
* $M$: Total memory cost in Kilobytes ($8 \le M \le 65536$).
* $B = 1024$ bytes: Size of one block ($256$ words of $32$-bit integers $\mathbb{Z}_{2^{32}}$).
* $p$: Parallelism degree (number of independent memory lanes, $1 \le p \le 16$).
* $N = \lfloor M / p \rfloor$: Number of blocks per lane.
* $T$: Time cost (number of passes over the memory matrix, $1 \le T \le 64$).
* $L_{\text{out}}$: Output length in bytes ($1 \le L_{\text{out}} \le 64$).
* $\mathcal{M}[l, i]$: The $i$-th block in lane $l$ ($l \in [0, p-1]$, $i \in [0, N-1]$).

---

## 2. Initial Seed Extraction ($H_0$)

Given password $P$ (where $|P| \ge 0$), salt $S$ (where $|S| \ge 8$ bytes), optional additional data $\text{AD}$, and parameters $(M, T, p, \text{mode}, L_{\text{out}})$:

$$H_0 = \text{SHA-512}\Big( \text{Header}_{20} \parallel \text{LP}(P,\ S,\ \text{AD}) \Big)$$

Where $\text{LP}(x_1, \ldots, x_n)$ denotes **length-prefixed encoding**: each field $x_i$ is preceded by its 4-byte little-endian length, preventing ambiguous-concatenation collisions. For example, $\text{LP}(\texttt{"abc"}, \texttt{"defg"}) \ne \text{LP}(\texttt{"abcd"}, \texttt{"efg"})$ even though their raw concatenations are identical.

$\text{Header}_{20}$ is a 20-byte domain-separation header with full-width fields:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 bytes (uint32LE) | $M$ (memoryCostKb) |
| 4 | 4 bytes (uint32LE) | $T$ (timeCost) |
| 8 | 4 bytes (uint32LE) | $p$ (parallelism) |
| 12 | 1 byte (uint8) | mode (0=hybrid, 1=independent, 2=dependent) |
| 13–15 | 3 bytes | reserved / zero padding |
| 16 | 4 bytes (uint32LE) | $L_{\text{out}}$ (outputLength) |

> [!IMPORTANT]
> `outputLength` is stored as a full `uint32` to prevent silent truncation. A former `uint8` encoding caused `outputLength=256` and `outputLength=0` to produce the same $H_0$.

Initial blocks $\mathcal{M}[l, k]$ are expanded from $H_0$ per chunk $c \in [0, 15]$:
$$\mathcal{M}[l, k][c] = \text{SHA-512}\Big( H_0 \parallel \text{uint32LE}(l) \parallel \text{uint32LE}(k) \parallel \text{uint32LE}(c) \Big)$$

Each chunk is derived independently (not via a hash chain) so the per-lane and per-block-index context is preserved across all 16 chunks.

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
   Used when $\text{mode} = \text{independent}$ or ($\text{mode} = \text{hybrid}$, $t = 0$, and $i < N/2$).

   A fresh 256-word address block $\mathcal{A}$ is constructed and permuted:
   $$\mathcal{A}[0..4] = (t,\; l,\; i,\; M,\; T)$$
   $$\mathcal{A}[w] \;\mathrel{\oplus}=\; \text{uint32LE}(H_0[4w\ldots 4w+3]) \quad \text{for } w \in [0, 7]$$
   $$\mathcal{A} \leftarrow \text{Permute}_{2D}(\mathcal{A})$$
   $$J_{\text{indep}} = \mathcal{A}[i \bmod 256]$$

   The XOR of $H_0$ words into the address block binds the data-independent access pattern to the password. Without this binding, an attacker could precompute the traversal graph once per configuration and reuse it across all cracking attempts.

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

Self-reference ($j = i$) is resolved by falling back to $j = (i - 1) \bmod N$.

This creates an exponential bias towards recently computed blocks, making memory eviction in pebbling games mathematically suboptimal for an attacker.

---

## 5. Asymmetric Trapdoor & Vault Masking

Let $K \in \{0, 1\}^{128..256}$ be a secret key held in a hardware secure enclave or passkey PRF ($|K| \ge 16$ bytes; 32 bytes recommended).

Let $\text{LP}(x_1, \ldots, x_n)$ denote **length-prefixed encoding** as defined in §2.

### 5.1 Sealing (Setup)
1. Compute memory-hard DAG output:
   $$D = \text{Aura}(P, S, M, T, p)$$
2. Compute Public Anchor — $K$ is the HMAC key, so the anchor cannot be evaluated or checked without $K$:
   $$A = \text{HMAC-SHA256}\big(K,\; \text{LP}(D, S)\big)$$
3. *(Masked Vault Mode — **default**)*:
   $$D_{\text{stored}} = D \oplus \text{HKDF-SHA256}(K, S, \texttt{"aura:vault:mask"})$$
   When unmasked: $D_{\text{stored}} = D$.

### 5.2 Verification
* **With Trapdoor Key $K$** (masked or unmasked):
  Re-derive $D' = \text{Aura}(P', S, M, T, p)$.
  Accept iff $A \stackrel{?}{=} \text{HMAC-SHA256}(K, \text{LP}(D', S))$.
* **Without Trapdoor Key $K$ (unmasked only)**:
  Re-derive $D' = \text{Aura}(P', S, M, T, p)$.
  Accept iff $D_{\text{stored}} \stackrel{?}{=} D'$ (timing-safe comparison).
* **Without Trapdoor Key $K$ (masked mode)**:
  Verification is **mathematically impossible** — $D_{\text{stored}}$ is indistinguishable from random bytes and the anchor requires $K$ to evaluate.

> [!IMPORTANT]
> The anchor $A = \text{HMAC-SHA256}(K, \text{LP}(D, S))$ makes $K$ cryptographically required to verify. An attacker who steals $D_{\text{stored}}$ and $A$ from the database cannot check candidate passwords against the anchor without possessing $K$. In masked mode, they cannot even run the MHF comparison directly.

### 5.3 Input Constraints Enforced at the API Boundary

| Parameter | Constraint | Rationale |
| :--- | :--- | :--- |
| Salt $S$ | $\|S\| \ge 8$ bytes | Prevents trivially rainbow-tabled salts |
| Trapdoor key $K$ | $\|K\| \ge 16$ bytes | Ensures at least 128-bit HMAC security |
| Memory cost $M$ | $8 \le M \le 65536$ (KB) | Prevents DoS via unbounded allocation |
| Time cost $T$ | $1 \le T \le 64$ | Prevents CPU exhaustion |
| Parallelism $p$ | $1 \le p \le 16$ | Prevents oversized lane allocation |
| Output length $L_{\text{out}}$ | $1 \le L_{\text{out}} \le 64$ bytes | SHA-512 output bound; use HKDF to expand further |
| Mode | ∈ {hybrid, independent, dependent} | Prevents silent degradation to unknown behaviour |
