/**
 * @epoch32/aura
 * Zero-dependency Edge-Native Asymmetric Memory-Hard Function (aMHF) & Hybrid KDF
 * Built for Cloudflare Workers, Edge Gateways, and Modern Browsers
 */

export {
	Aura,
	type AuraHashResult,
	type AuraOptions,
	type AuraSealedEnvelope,
} from "./core/aura";
export {
	BLOCK_SIZE_BYTES,
	BLOCK_SIZE_WORDS,
	copyBlock,
	mixBlocks,
	permuteBlock,
	xorBlock,
} from "./core/block";
export {
	type AuraMode,
	MemoryDag,
	type MemoryDagConfig,
} from "./core/memory-dag";
export {
	type TrapdoorCommitment,
	TrapdoorEngine,
} from "./trapdoor/trapdoor";
export {
	base64UrlToBytes,
	bigIntToBytesLE,
	bytesToBase64Url,
	bytesToBigIntLE,
	bytesToHex,
	bytesToUtf8,
	concatBytes,
	constantTimeEqual,
	hexToBytes,
	randomBytes,
	utf8ToBytes,
} from "./encoding/bytes";
