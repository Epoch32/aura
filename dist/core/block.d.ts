/**
 * AURA 1024-Byte Block Operations & High-Performance Word Mixing
 * Optimized for V8 / workerd 32-bit JIT with Full 2D Cross-Block Diffusion
 */
export declare const BLOCK_SIZE_BYTES = 1024;
export declare const BLOCK_SIZE_WORDS: number;
/**
 * Fast 32-bit word-level in-place block XOR: dst ^= src
 */
export declare function xorBlock(dst: Uint32Array, src: Uint32Array): void;
/**
 * Fast 32-bit word-level copy: dst = src
 */
export declare function copyBlock(dst: Uint32Array, src: Uint32Array): void;
/**
 * Permutes a 1024-byte block using 2-Dimensional Cross-Block ARX Rounds
 * Phase 1: Row rounds (within sixteen 16-word sub-blocks)
 * Phase 2: Column & Diagonal rounds (spanning across all 256 words of the 1KB block)
 * Defeats divide-and-conquer / bit-slice GPU/ASIC attacks.
 */
export declare function permuteBlock(block: Uint32Array): void;
/**
 * AURA Core Block Mixer (Davies-Meyer Feed-Forward):
 * out = Permute(prev ^ ref) ^ prev ^ ref
 */
export declare function mixBlocks(prevBlock: Uint32Array, refBlock: Uint32Array, outBlock: Uint32Array): void;
