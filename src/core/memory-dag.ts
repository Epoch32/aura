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
	private addressBuffer: Uint32Array;

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

		this.config = config;
		this.totalBlocks = config.memoryCostKb;
		this.blocksPerLane = Math.floor(this.totalBlocks / config.parallelism);

		// Allocate contiguous ArrayBuffer
		this.memoryBuffer = new ArrayBuffer(this.totalBlocks * BLOCK_SIZE_BYTES);
		this.blocks = new Array(this.totalBlocks);
		this.addressBuffer = new Uint32Array(BLOCK_SIZE_WORDS);

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
		const header = new Uint8Array(16);
		const view = new DataView(header.buffer);
		view.setUint32(0, config.memoryCostKb, true);
		view.setUint32(4, config.timeCost, true);
		view.setUint32(8, config.parallelism, true);
		view.setUint8(12, config.mode === "hybrid" ? 0 : config.mode === "independent" ? 1 : 2);
		view.setUint8(13, config.outputLength);

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

				let currentSeed = concatBytes(h0, blockHeader);
				for (let chunk = 0; chunk < BLOCK_SIZE_BYTES / 64; chunk++) {
					const hash = await crypto.subtle.digest("SHA-512", currentSeed as unknown as BufferSource);
					const hashBytes = new Uint8Array(hash);
					targetU8.set(hashBytes, chunk * 64);
					currentSeed = hashBytes;
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
	): { refLane: number; refIndex: number } {
		const isFirstHalf = index < Math.floor(this.blocksPerLane / 2);
		const isDataIndependent =
			this.config.mode === "independent" ||
			(this.config.mode === "hybrid" && pass === 0 && isFirstHalf);

		let pseudoRand: number;
		if (isDataIndependent) {
			// Multi-round ARX address generation preventing parallel speculative pre-fetching
			const addrBlock = this.addressBuffer;
			addrBlock[0] = pass;
			addrBlock[1] = lane;
			addrBlock[2] = index;
			addrBlock[3] = this.config.memoryCostKb;
			addrBlock[4] = this.config.timeCost;
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
		await this.initializeFirstBlocks(h0);

		const tempBlock = new Uint32Array(BLOCK_SIZE_WORDS);

		for (let pass = 0; pass < this.config.timeCost; pass++) {
			for (let lane = 0; lane < this.config.parallelism; lane++) {
				const startIdx = pass === 0 ? 2 : 0;

				for (let i = startIdx; i < this.blocksPerLane; i++) {
					const prevIdx = i === 0 ? this.blocksPerLane - 1 : i - 1;
					const prevBlock = this.getBlock(lane, prevIdx);

					const { refLane, refIndex } = this.computeReferenceIndex(pass, lane, i, prevBlock);
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
