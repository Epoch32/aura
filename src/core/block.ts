/**
 * AURA 1024-Byte Block Operations & High-Performance Word Mixing
 * Optimized for V8 / workerd 32-bit JIT with Full 2D Cross-Block Diffusion
 */

export const BLOCK_SIZE_BYTES = 1024;
export const BLOCK_SIZE_WORDS = BLOCK_SIZE_BYTES / 4; // 256 uint32 words

/**
 * Fast 32-bit word-level in-place block XOR: dst ^= src
 */
export function xorBlock(dst: Uint32Array, src: Uint32Array): void {
	for (let i = 0; i < BLOCK_SIZE_WORDS; i++) {
		dst[i] ^= src[i];
	}
}

/**
 * Fast 32-bit word-level copy: dst = src
 */
export function copyBlock(dst: Uint32Array, src: Uint32Array): void {
	dst.set(src);
}

/**
 * 32-bit circular left rotation
 */
function rotl(v: number, n: number): number {
	return ((v << n) | (v >>> (32 - n))) | 0;
}

/**
 * 32-bit ARX Quarter-Round Permutation
 * a = a + b; d = rotl(d ^ a, 16); c = c + d; b = rotl(b ^ c, 12);
 * a = a + b; d = rotl(d ^ a, 8);  c = c + d; b = rotl(b ^ c, 7);
 */
function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
	state[a] = (state[a] + state[b]) | 0;
	state[d] = rotl(state[d] ^ state[a], 16);
	state[c] = (state[c] + state[d]) | 0;
	state[b] = rotl(state[b] ^ state[c], 12);

	state[a] = (state[a] + state[b]) | 0;
	state[d] = rotl(state[d] ^ state[a], 8);
	state[c] = (state[c] + state[d]) | 0;
	state[b] = rotl(state[b] ^ state[c], 7);
}

/**
 * Permutes a 1024-byte block using 2-Dimensional Cross-Block ARX Rounds
 * Phase 1: Row rounds (within sixteen 16-word sub-blocks)
 * Phase 2: Column & Diagonal rounds (spanning across all 256 words of the 1KB block)
 * Defeats divide-and-conquer / bit-slice GPU/ASIC attacks.
 */
export function permuteBlock(block: Uint32Array): void {
	// 1. Row Rounds: Permute each 16-word row of the 16x16 word matrix
	for (let offset = 0; offset < BLOCK_SIZE_WORDS; offset += 16) {
		// Column rounds within 16-word row
		quarterRound(block, offset + 0, offset + 4, offset + 8, offset + 12);
		quarterRound(block, offset + 1, offset + 5, offset + 9, offset + 13);
		quarterRound(block, offset + 2, offset + 6, offset + 10, offset + 14);
		quarterRound(block, offset + 3, offset + 7, offset + 11, offset + 15);

		// Diagonal rounds within 16-word row
		quarterRound(block, offset + 0, offset + 5, offset + 10, offset + 15);
		quarterRound(block, offset + 1, offset + 6, offset + 11, offset + 12);
		quarterRound(block, offset + 2, offset + 7, offset + 8, offset + 13);
		quarterRound(block, offset + 3, offset + 4, offset + 9, offset + 14);
	}

	// 2. Column Rounds: Permute each 16-word column across all 16 rows (stride 16)
	for (let col = 0; col < 16; col++) {
		quarterRound(block, col + 0, col + 64, col + 128, col + 192);
		quarterRound(block, col + 16, col + 80, col + 144, col + 208);
		quarterRound(block, col + 32, col + 96, col + 160, col + 224);
		quarterRound(block, col + 48, col + 112, col + 176, col + 240);

		quarterRound(block, col + 0, col + 80, col + 160, col + 240);
		quarterRound(block, col + 16, col + 96, col + 176, col + 192);
		quarterRound(block, col + 32, col + 112, col + 128, col + 208);
		quarterRound(block, col + 48, col + 64, col + 144, col + 224);
	}

	// 3. Cross-Block Diagonal Rounds: Non-linear diffusion across shifted columns and row groups
	for (let col = 0; col < 16; col++) {
		const c1 = ((col + 1) & 15) + 16;
		const c2 = ((col + 2) & 15) + 32;
		const c3 = ((col + 3) & 15) + 48;
		quarterRound(block, col, c1 + 64, c2 + 128, c3 + 192);
		quarterRound(block, col + 16, c2 + 64, c3 + 128, col + 192);
		quarterRound(block, col + 32, c3 + 64, col + 128, c1 + 192);
		quarterRound(block, col + 48, col + 64, c1 + 128, c2 + 192);
	}
}

/**
 * AURA Core Block Mixer (Davies-Meyer Feed-Forward):
 * out = Permute(prev ^ ref) ^ prev ^ ref
 */
export function mixBlocks(
	prevBlock: Uint32Array,
	refBlock: Uint32Array,
	outBlock: Uint32Array,
): void {
	// 1. out = prev ^ ref
	for (let i = 0; i < BLOCK_SIZE_WORDS; i++) {
		outBlock[i] = prevBlock[i] ^ refBlock[i];
	}

	// 2. Full 2D Permutation across all 1024 bytes
	permuteBlock(outBlock);

	// 3. Davies-Meyer feed-forward XOR: out ^= (prev ^ ref)
	for (let i = 0; i < BLOCK_SIZE_WORDS; i++) {
		outBlock[i] ^= prevBlock[i] ^ refBlock[i];
	}
}
