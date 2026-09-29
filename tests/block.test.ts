import { describe, expect, it } from "bun:test";
import {
	BLOCK_SIZE_BYTES,
	BLOCK_SIZE_WORDS,
	copyBlock,
	mixBlocks,
	permuteBlock,
	xorBlock,
} from "../src/core/block";

describe("AURA Block Operations", () => {
	it("should correctly perform 32-bit word-level in-place XOR", () => {
		const a = new Uint32Array(BLOCK_SIZE_WORDS);
		const b = new Uint32Array(BLOCK_SIZE_WORDS);

		a[0] = 0x12345678;
		a[10] = 0xffffffff;

		b[0] = 0x00000008;
		b[10] = 0x00000001;

		xorBlock(a, b);

		expect(a[0]).toBe(0x12345670);
		expect(a[10]).toBe(0xfffffffe);
	});

	it("should copy block data accurately", () => {
		const src = new Uint32Array(BLOCK_SIZE_WORDS);
		const dst = new Uint32Array(BLOCK_SIZE_WORDS);

		src[42] = 0xdeadbeef;
		copyBlock(dst, src);

		expect(dst[42]).toBe(0xdeadbeef);
	});

	it("should provide non-linear diffusion through permuteBlock", () => {
		const block1 = new Uint32Array(BLOCK_SIZE_WORDS);
		const block2 = new Uint32Array(BLOCK_SIZE_WORDS);

		block1[0] = 1;
		block2[0] = 2;

		permuteBlock(block1);
		permuteBlock(block2);

		// Diffusion check: changing 1 bit should change many words
		let diffWords = 0;
		for (let i = 0; i < 16; i++) {
			if (block1[i] !== block2[i]) {
				diffWords++;
			}
		}
		expect(diffWords).toBeGreaterThan(8);
	});

	it("should mix previous and reference blocks deterministically", () => {
		const prev = new Uint32Array(BLOCK_SIZE_WORDS);
		const ref = new Uint32Array(BLOCK_SIZE_WORDS);
		const out1 = new Uint32Array(BLOCK_SIZE_WORDS);
		const out2 = new Uint32Array(BLOCK_SIZE_WORDS);

		prev[0] = 0xcafe;
		ref[0] = 0xbabe;

		mixBlocks(prev, ref, out1);
		mixBlocks(prev, ref, out2);

		expect(out1[0]).toBe(out2[0]);
		expect(out1[1]).toBe(out2[1]);
		expect(out1[0]).not.toBe(0);
	});
});
