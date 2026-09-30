/**
 * AURA Memory DAG (Directed Acyclic Graph) Execution Engine
 * Supports Hybrid (Argon2id-style), Data-Independent, and Data-Dependent Modes
 * Hardened with Non-Uniform Quadratic Indexing (TMTO Defense) & ARX Address Expansion
 */

import { concatBytes } from "../encoding/bytes";
import { BLOCK_SIZE_BYTES, BLOCK_SIZE_WORDS, copyBlock, mixBlocks, permuteBlock } from "./block";

export type AuraMode = "hybrid" | "independent" | "dependent";

export interface MemoryDagConfig {
	readonly memoryCostKb: number; // e.g. 1024 to 65536
	readonly timeCost: number;     // Number of passes (e.g. 1 to 10)
	readonly parallelism: number;  // Number of lanes (e.g. 1 to 4)
	readonly mode: AuraMode;
	readonly outputLength: number; // e.g. 32 or 64 bytes
}

export class MemoryDag {
	readonly config: MemoryDagConfig;
	readonly totalBlocks: number;
	readonly blocksPerLane: number;

	private memoryBuffer: ArrayBuffer;
	private blocks: Uint32Array[];
	private executed = false; // guards against accidental re-use of the same instance

	constructor(config: MemoryDagConfig) {
		if (config.memoryCostKb < 8) {
			throw new Error("Memory cost must be at least 8 KB");
		}
		if (config.parallelism < 1) {
			throw new Error("Parallelism must be at least 1");
		}
		if (config.timeCost < 1) {
			throw new Error("Time cost must be at least 1 pass");
		}
		if (config.outputLength < 1 || config.outputLength > 64) {
			// SHA-512 produces 64 bytes. Requesting more silently truncates to 64,
			// breaking domain separation between different outputLength values > 64.
			// Callers who need longer output should run HKDF over the result.
			throw new Error("outputLength must be between 1 and 64 bytes; use HKDF to expand the output further");
		}

		this.config = config;
		this.totalBlocks = config.memoryCostKb;
		this.blocksPerLane = Math.floor(this.totalBlocks / config.parallelism);

		// Allocate contiguous ArrayBuffer
		this.memoryBuffer = new ArrayBuffer(this.totalBlocks * BLOCK_SIZE_BYTES);
		this.blocks = new Array(this.totalBlocks);

		for (let i = 0; i < this.totalBlocks; i++) {
			this.blocks[i] = new Uint32Array(
				this.memoryBuffer,
				i * BLOCK_SIZE_BYTES,
				BLOCK_SIZE_WORDS,
			);
		}
	}

	private getBlock(lane: number, index: number): Uint32Array {
		return this.blocks[lane * this.blocksPerLane + index];
	}

	/**
	 * Computes initial 64-byte seed H0
	 */
	static async computeInitialSeed(
		password: Uint8Array,
		salt: Uint8Array,
		config: MemoryDagConfig,
		additionalData?: Uint8Array,
	): Promise<Uint8Array> {
		// 20-byte domain-separation header — all fields are full-width to prevent silent truncation.
		// outputLength is uint32 (not uint8) so values > 255 are correctly domain-separated.
		const header = new Uint8Array(20);
		const view = new DataView(header.buffer);
		view.setUint32(0, config.memoryCostKb, true);
		view.setUint32(4, config.timeCost, true);
		view.setUint32(8, config.parallelism, true);
		view.setUint8(12, config.mode === "hybrid" ? 0 : config.mode === "independent" ? 1 : 2);
		// bytes 13–15: reserved / zero padding
		view.setUint32(16, config.outputLength, true);

		const payload = concatBytes(
			header,
			password,
			salt,
			additionalData ?? new Uint8Array(0),
		);

		const digest = await crypto.subtle.digest("SHA-512", payload as unknown as BufferSource);
		return new Uint8Array(digest);
	}

	/**
	 * Initializes Block 0 and Block 1 for each lane using H0
	 */
	async initializeFirstBlocks(h0: Uint8Array): Promise<void> {
		for (let lane = 0; lane < this.config.parallelism; lane++) {
			for (let idx = 0; idx < 2; idx++) {
				const blockHeader = new Uint8Array(8);
				const view = new DataView(blockHeader.buffer);
				view.setUint32(0, lane, true);
				view.setUint32(4, idx, true);

				// Expand 64-byte H0 into 1024-byte block using WebCrypto HKDF / SHA-512
				const target = this.getBlock(lane, idx);
				const targetU8 = new Uint8Array(target.buffer, target.byteOffset, BLOCK_SIZE_BYTES);

				// Derive each 64-byte chunk independently using SHA-512(h0 || lane || idx || chunk).
				// The original design re-hashed only the previous output (a simple hash chain),
				// which dropped the lane/idx context after chunk 0 and weakened block diversity.
				// Including the chunk counter here gives proper XOF-style domain separation.
				for (let chunk = 0; chunk < BLOCK_SIZE_BYTES / 64; chunk++) {
					const chunkTag = new Uint8Array(4);
					new DataView(chunkTag.buffer).setUint32(0, chunk, true);
					const chunkInput = concatBytes(h0, blockHeader, chunkTag);
					const hash = await crypto.subtle.digest("SHA-512", chunkInput as unknown as BufferSource);
					targetU8.set(new Uint8Array(hash), chunk * 64);
				}
			}
		}
	}

	/**
	 * Computes the reference block index j using Quadratic Non-Uniform Mapping (TMTO Defense)
	 */
	private computeReferenceIndex(
		pass: number,
		lane: number,
		index: number,
		prevBlock: Uint32Array,
		h0: Uint8Array,
	): { refLane: number; refIndex: number } {
		const isFirstHalf = index < Math.floor(this.blocksPerLane / 2);
		const isDataIndependent =
			this.config.mode === "independent" ||
			(this.config.mode === "hybrid" && pass === 0 && isFirstHalf);

		let pseudoRand: number;
		if (isDataIndependent) {
			// Allocate a fresh block locally so concurrent lane execution never shares state.
			// (The shared class-level addressBuffer has been removed for this reason.)
			const addrBlock = new Uint32Array(BLOCK_SIZE_WORDS);
			addrBlock[0] = pass;
			addrBlock[1] = lane;
			addrBlock[2] = index;
			addrBlock[3] = this.config.memoryCostKb;
			addrBlock[4] = this.config.timeCost;
			// Bind address block to the password via H0 so that the data-independent
			// access pattern is unique per password, even across identical configs.
			// Without this, an attacker could precompute the traversal graph once and
			// reuse it for all cracking attempts against the same configuration.
			// H0 is 64 bytes; read the first 8 words as little-endian uint32.
			for (let w = 0; w < 8; w++) {
				const off = w * 4;
				addrBlock[w] ^= (h0[off] | (h0[off + 1] << 8) | (h0[off + 2] << 16) | (h0[off + 3] << 24)) >>> 0;
			}
			permuteBlock(addrBlock);
			pseudoRand = addrBlock[index % BLOCK_SIZE_WORDS] >>> 0;
		} else {
			// Data-dependent index derived from the first word of the previous block
			pseudoRand = prevBlock[0] >>> 0;
		}

		// Available reference window size
		const windowSize = pass === 0 ? index : this.blocksPerLane - 1;
		if (windowSize <= 1) {
			return { refLane: lane, refIndex: 0 };
		}

		// Quadratic non-uniform mapping (Argon2 TMTO Defense):
		// Heavily biases reference block lookups towards recently computed blocks.
		// Discarding recent blocks in memory pebbling becomes exponentially expensive.
		const jBig = BigInt(pseudoRand >>> 0);
		const x = (jBig * jBig) >> 32n;
		const y = (BigInt(windowSize) * x) >> 32n;
		const offset = windowSize - 1 - Number(y);

		const refIndex = pass === 0 ? offset : (index + 1 + offset) % this.blocksPerLane;

		return { refLane: lane, refIndex };
	}

	/**
	 * Executes the full multi-pass memory mixing graph
	 */
	async execute(h0: Uint8Array): Promise<Uint8Array> {
		if (this.executed) {
			// The memory arena is mutated in-place. Re-using the same instance produces
			// incorrect output because initializeFirstBlocks only resets blocks 0 and 1.
			throw new Error("MemoryDag instance has already been executed; create a new instance for each derivation");
		}
		this.executed = true;
		await this.initializeFirstBlocks(h0);

		const tempBlock = new Uint32Array(BLOCK_SIZE_WORDS);

		for (let pass = 0; pass < this.config.timeCost; pass++) {
			for (let lane = 0; lane < this.config.parallelism; lane++) {
				const startIdx = pass === 0 ? 2 : 0;

				for (let i = startIdx; i < this.blocksPerLane; i++) {
					const prevIdx = i === 0 ? this.blocksPerLane - 1 : i - 1;
					const prevBlock = this.getBlock(lane, prevIdx);

					let { refLane, refIndex } = this.computeReferenceIndex(pass, lane, i, prevBlock, h0);

					// Prevent self-reference: mixBlocks reads from refBlock and writes to currentBlock.
					// If refBlock === currentBlock, the XOR and permute operate on a partially-written
					// array, producing incorrect and non-deterministic output.
					if (refLane === lane && refIndex === i) {
						refIndex = (i - 1 + this.blocksPerLane) % this.blocksPerLane;
					}

					const refBlock = this.getBlock(refLane, refIndex);
					const currentBlock = this.getBlock(lane, i);

					if (pass === 0) {
						mixBlocks(prevBlock, refBlock, currentBlock);
					} else {
						// On subsequent passes, mix and XOR with existing content
						mixBlocks(prevBlock, refBlock, tempBlock);
						for (let k = 0; k < BLOCK_SIZE_WORDS; k++) {
							currentBlock[k] ^= tempBlock[k];
						}
					}
				}
			}
		}

		// Final block reduction: Column XOR of all final lane blocks
		const finalBlock = new Uint32Array(BLOCK_SIZE_WORDS);
		copyBlock(finalBlock, this.getBlock(0, this.blocksPerLane - 1));

		for (let l = 1; l < this.config.parallelism; l++) {
			const laneFinal = this.getBlock(l, this.blocksPerLane - 1);
			for (let k = 0; k < BLOCK_SIZE_WORDS; k++) {
				finalBlock[k] ^= laneFinal[k];
			}
		}

		// Hash final block to produce outputLength bytes
		const finalU8 = new Uint8Array(finalBlock.buffer, finalBlock.byteOffset, BLOCK_SIZE_BYTES);
		const finalDigest = await crypto.subtle.digest("SHA-512", finalU8 as unknown as BufferSource);
		const digestBytes = new Uint8Array(finalDigest);

		return digestBytes.slice(0, this.config.outputLength);
	}
}
