/**
 * AURA (Asymmetric Unkeyed-Resistant Algorithm)
 * Edge-Native Asymmetric Memory-Hard Function & KDF Engine
 * Main High-Level API with Hardened Memory DAG & Asymmetric Vault Masking
 */

import {
	base64UrlToBytes,
	bytesToBase64Url,
	concatBytes,
	constantTimeEqual,
	encodeLengthPrefixed,
	randomBytes,
	utf8ToBytes,
} from "../encoding/bytes";
import { AuraMode, MemoryDag, MemoryDagConfig } from "./memory-dag";
import { TrapdoorEngine } from "../trapdoor/trapdoor";

export interface AuraVerifyOptions {
	readonly additionalData?: Uint8Array;
}

export interface AuraOptions {
	readonly memoryCostKb?: number; // Default: 4096 KB (4 MB)
	readonly timeCost?: number;     // Default: 2 passes
	readonly parallelism?: number;  // Default: 1 lane
	readonly mode?: AuraMode;       // Default: "hybrid" (Argon2id-style)
	readonly outputLength?: number; // Default: 32 bytes
	readonly salt?: Uint8Array;
	readonly additionalData?: Uint8Array;
	readonly masked?: boolean;      // Default: true (enables HKDF vault masking; set false only if trapdoor key is unavailable at verify time)
}

export interface AuraHashResult {
	readonly encoded: string;
	readonly rawHash: Uint8Array;
	readonly salt: Uint8Array;
	readonly config: MemoryDagConfig;
}

export interface AuraSealedEnvelope {
	readonly version: number;
	readonly mode: AuraMode;
	readonly memoryCostKb: number;
	readonly timeCost: number;
	readonly parallelism: number;
	readonly masked?: boolean;
	readonly salt: string;         // Base64URL
	readonly publicAnchor: string; // Base64URL
	readonly dagOutput: string;    // Base64URL (Masked if masked=true)
}

export class Aura {
	static readonly VERSION = 1;

	static readonly DEFAULT_CONFIG: MemoryDagConfig = {
		memoryCostKb: 4096,
		timeCost: 2,
		parallelism: 1,
		mode: "hybrid",
		outputLength: 32,
	};

	/**
	 * Resolves options with default values
	 */
	private static resolveConfig(options?: AuraOptions): MemoryDagConfig {
		return {
			memoryCostKb: options?.memoryCostKb ?? Aura.DEFAULT_CONFIG.memoryCostKb,
			timeCost: options?.timeCost ?? Aura.DEFAULT_CONFIG.timeCost,
			parallelism: options?.parallelism ?? Aura.DEFAULT_CONFIG.parallelism,
			mode: options?.mode ?? Aura.DEFAULT_CONFIG.mode,
			outputLength: options?.outputLength ?? Aura.DEFAULT_CONFIG.outputLength,
		};
	}

	private static toBytes(input: string | Uint8Array): Uint8Array {
		return typeof input === "string" ? utf8ToBytes(input) : input;
	}

	/**
	 * Derives raw key material using the memory-hard graph
	 */
	static async deriveKey(
		password: string | Uint8Array,
		salt: Uint8Array,
		options?: AuraOptions,
	): Promise<Uint8Array> {
		const config = Aura.resolveConfig(options);
		const pwdBytes = Aura.toBytes(password);
		if (salt.length < 8 || salt.length > 64) {
			throw new Error("Salt must be between 8 and 64 bytes; 16 bytes (128 bits) is recommended");
		}

		const h0 = await MemoryDag.computeInitialSeed(
			pwdBytes,
			salt,
			config,
			options?.additionalData,
		);

		const dag = new MemoryDag(config);
		return dag.execute(h0);
	}

	/**
	 * Hashes a password into a standard PHC-formatted AURA string
	 * Format: $aura$v=1$m=4096,t=2,p=1,mode=hybrid$salt$hash
	 */
	static async hash(
		password: string | Uint8Array,
		options?: AuraOptions,
	): Promise<AuraHashResult> {
		const config = Aura.resolveConfig(options);
		const salt = options?.salt ?? randomBytes(16);
		if (salt.length < 8 || salt.length > 64) {
			throw new Error("Salt must be between 8 and 64 bytes; 16 bytes (128 bits) is recommended");
		}
		const rawHash = await Aura.deriveKey(password, salt, options);

		const encoded = [
			"$aura",
			`v=${Aura.VERSION}`,
			`m=${config.memoryCostKb},t=${config.timeCost},p=${config.parallelism},mode=${config.mode}`,
			bytesToBase64Url(salt),
			bytesToBase64Url(rawHash),
		].join("$");

		return {
			encoded,
			rawHash,
			salt,
			config,
		};
	}

	private static encodeEnvelopeMeta(
		version: number,
		memoryCostKb: number,
		timeCost: number,
		parallelism: number,
		mode: AuraMode,
		masked: boolean,
		outputLength: number,
		additionalData?: Uint8Array,
	): Uint8Array {
		const meta = new Uint8Array(22);
		const view = new DataView(meta.buffer);
		view.setUint32(0, version, true);
		view.setUint32(4, memoryCostKb, true);
		view.setUint32(8, timeCost, true);
		view.setUint32(12, parallelism, true);
		view.setUint8(16, mode === "hybrid" ? 0 : mode === "independent" ? 1 : 2);
		view.setUint8(17, masked ? 1 : 0);
		view.setUint32(18, outputLength, true);
		return concatBytes(meta, encodeLengthPrefixed(additionalData ?? new Uint8Array(0)));
	}

	/**
	 * Seals a secret with an Asymmetric Trapdoor Key
	 * If options.masked = true, encrypts dagOutput under K so offline dictionary searches are impossible.
	 */
	static async sealWithTrapdoor(
		password: string | Uint8Array,
		trapdoorKey: Uint8Array,
		options?: AuraOptions,
	): Promise<AuraSealedEnvelope> {
		const config = Aura.resolveConfig(options);
		const salt = options?.salt ?? randomBytes(16);
		if (salt.length < 8 || salt.length > 64) {
			throw new Error("Salt must be between 8 and 64 bytes; 16 bytes (128 bits) is recommended");
		}
		const pwdBytes = Aura.toBytes(password);
		const isMasked = options?.masked ?? true;

		// 1. Compute Memory-Hard DAG Output
		const dagOutput = await Aura.deriveKey(pwdBytes, salt, options);

		// 2. Compute Public Anchor: HMAC-SHA256(K, LP(dagOutput, salt, password, envelopeMeta))
		//    Binds plaintext dagOutput, salt, password, and envelope parameters under K,
		//    enabling O(1) verification (< 0.5 ms) for key holders and authenticating the envelope.
		const envelopeMeta = Aura.encodeEnvelopeMeta(
			Aura.VERSION,
			config.memoryCostKb,
			config.timeCost,
			config.parallelism,
			config.mode,
			isMasked,
			dagOutput.length,
			options?.additionalData,
		);
		const publicAnchor = await TrapdoorEngine.computePublicAnchor(
			dagOutput,
			trapdoorKey,
			salt,
			pwdBytes,
			envelopeMeta,
		);

		// 3. Optional Vault Masking: storedDagOutput = dagOutput ^ HKDF(K, salt)
		//    Blinds the stored bytes so an attacker without K cannot run the MHF
		//    offline against the stored dagOutput.
		const storedDagOutput = isMasked
			? await TrapdoorEngine.maskDagOutput(dagOutput, trapdoorKey, salt)
			: dagOutput;

		return {
			version: Aura.VERSION,
			mode: config.mode,
			memoryCostKb: config.memoryCostKb,
			timeCost: config.timeCost,
			parallelism: config.parallelism,
			masked: isMasked,
			salt: bytesToBase64Url(salt),
			publicAnchor: bytesToBase64Url(publicAnchor),
			dagOutput: bytesToBase64Url(storedDagOutput),
		};
	}

	/**
	 * Verifies a password against a standard PHC hash or Trapdoor Sealed Envelope
	 */
	static async verify(
		password: string | Uint8Array,
		hashOrEnvelope: string | AuraSealedEnvelope,
		trapdoorKeyOrOptions?: Uint8Array | AuraVerifyOptions,
		options?: AuraVerifyOptions,
	): Promise<boolean> {
		try {
			const isKey = trapdoorKeyOrOptions instanceof Uint8Array;
			const trapdoorKey = isKey ? trapdoorKeyOrOptions : undefined;
			const verifyOpts = isKey ? options : trapdoorKeyOrOptions;
			return await Aura._verify(password, hashOrEnvelope, trapdoorKey, verifyOpts);
		} catch {
			return false;
		}
	}

	private static async _verify(
		password: string | Uint8Array,
		hashOrEnvelope: string | AuraSealedEnvelope,
		trapdoorKey?: Uint8Array,
		options?: AuraVerifyOptions,
	): Promise<boolean> {
		const pwdBytes = Aura.toBytes(password);

		// Case A: Trapdoor Envelope Verification
		if (typeof hashOrEnvelope === "object") {
			if (
				hashOrEnvelope === null ||
				typeof hashOrEnvelope.salt !== "string" ||
				typeof hashOrEnvelope.publicAnchor !== "string" ||
				typeof hashOrEnvelope.dagOutput !== "string"
			) {
				return false;
			}
			// Guard against oversized salt, publicAnchor, and dagOutput blobs before decoding.
			const approxSaltLen = Math.floor((hashOrEnvelope.salt.length * 3) / 4);
			const approxAnchorLen = Math.floor((hashOrEnvelope.publicAnchor.length * 3) / 4);
			const approxDecodedLen = Math.floor((hashOrEnvelope.dagOutput.length * 3) / 4);
			if (
				approxSaltLen < 8 || approxSaltLen > 64 ||
				approxAnchorLen !== 32 ||
				approxDecodedLen < 1 || approxDecodedLen > 64
			) {
				return false;
			}
			const salt = base64UrlToBytes(hashOrEnvelope.salt);
			const publicAnchor = base64UrlToBytes(hashOrEnvelope.publicAnchor);
			const rawDagStored = base64UrlToBytes(hashOrEnvelope.dagOutput);
			// Validate envelope params — mirrors the bounds enforced in the PHC string path
			// to prevent DoS via enormous allocation, CPU exhaustion, or silent mode degradation.
			const VALID_ENV_MODES: AuraMode[] = ["hybrid", "independent", "dependent"];
			if (
				hashOrEnvelope.version !== Aura.VERSION ||
				!Number.isInteger(hashOrEnvelope.memoryCostKb) || hashOrEnvelope.memoryCostKb < 8   || hashOrEnvelope.memoryCostKb > 65536 ||
				!Number.isInteger(hashOrEnvelope.timeCost)     || hashOrEnvelope.timeCost < 1        || hashOrEnvelope.timeCost > 64 ||
				!Number.isInteger(hashOrEnvelope.parallelism)  || hashOrEnvelope.parallelism < 1     || hashOrEnvelope.parallelism > 16 ||
				Math.floor(hashOrEnvelope.memoryCostKb / hashOrEnvelope.parallelism) < 4 ||
				!VALID_ENV_MODES.includes(hashOrEnvelope.mode)
			) {
				return false;
			}
			const isMasked = Boolean(hashOrEnvelope.masked);
			const envelopeMeta = Aura.encodeEnvelopeMeta(
				hashOrEnvelope.version,
				hashOrEnvelope.memoryCostKb,
				hashOrEnvelope.timeCost,
				hashOrEnvelope.parallelism,
				hashOrEnvelope.mode,
				isMasked,
				rawDagStored.length,
				options?.additionalData,
			);

			// Masked Vault Mode: dagOutput is blinded under K.
			// Unmask rawDagStored in O(1) via HKDF and verify the HMAC anchor in O(1) (< 0.5 ms).
			if (isMasked) {
				if (!trapdoorKey) {
					return false; // Cannot verify masked envelope without trapdoor key
				}
				const unmaskedDag = await TrapdoorEngine.maskDagOutput(rawDagStored, trapdoorKey, salt);
				return TrapdoorEngine.verifyWithTrapdoor(
					unmaskedDag,
					salt,
					publicAnchor,
					trapdoorKey,
					pwdBytes,
					envelopeMeta,
				);
			}

			// Fast Path (Unmasked + trapdoor key): O(1) HMAC check without executing the MHF.
			if (trapdoorKey) {
				return TrapdoorEngine.verifyWithTrapdoor(
					rawDagStored,
					salt,
					publicAnchor,
					trapdoorKey,
					pwdBytes,
					envelopeMeta,
				);
			}

			// Slow Path (Unmasked, no trapdoor key): recompute Memory-Hard DAG and compare directly.
			const dagOptions = {
				memoryCostKb: hashOrEnvelope.memoryCostKb,
				timeCost: hashOrEnvelope.timeCost,
				parallelism: hashOrEnvelope.parallelism,
				mode: hashOrEnvelope.mode,
				outputLength: rawDagStored.length,
				additionalData: options?.additionalData,
			};
			const computedDag = await Aura.deriveKey(pwdBytes, salt, dagOptions);
			return constantTimeEqual(rawDagStored, computedDag);
		}

		// Case B: Standard PHC Formatted String Verification
		if (typeof hashOrEnvelope !== "string" || hashOrEnvelope.length > 512) {
			return false;
		}
		const rawParts = hashOrEnvelope.split("$");
		if (rawParts.length !== 6 || rawParts[0] !== "") {
			return false;
		}
		const parts = rawParts.slice(1);
		if (parts[0] !== "aura" || parts.some((p) => p.length === 0)) {
			return false;
		}

		// Validate version — reject hashes from unknown future versions
		if (parts[1] !== `v=${Aura.VERSION}`) {
			return false;
		}

		// Parse params — reject duplicate or unknown keys and non-integer values
		// to prevent parameter injection attacks (e.g. "m=4096,...,m=64" or "m=4096xyz").
		const ALLOWED_KEYS = new Set(["m", "t", "p", "mode"]);
		const paramStr = parts[2];
		const params = new Map<string, string>();
		for (const kv of paramStr.split(",")) {
			const eqParts = kv.split("=");
			if (eqParts.length !== 2) {
				return false;
			}
			const [k, v] = eqParts;
			if (!ALLOWED_KEYS.has(k) || params.has(k) || v.length === 0) {
				return false;
			}
			params.set(k, v);
		}

		const mStr = params.get("m");
		const tStr = params.get("t");
		const pStr = params.get("p");
		const modeStr = params.get("mode");
		if (
			!mStr || !/^\d+$/.test(mStr) ||
			!tStr || !/^\d+$/.test(tStr) ||
			!pStr || !/^\d+$/.test(pStr) ||
			!modeStr
		) {
			return false;
		}

		const memoryCostKb = Number.parseInt(mStr, 10);
		const timeCost = Number.parseInt(tStr, 10);
		const parallelism = Number.parseInt(pStr, 10);
		const mode = modeStr as AuraMode;

		// Validate parameter ranges — prevents DoS via enormous memory allocation or
		// unbounded computation, and rejects unknown mode strings that would silently
		// fall through to data-dependent indexing.
		if (
			Number.isNaN(memoryCostKb) || memoryCostKb < 8 || memoryCostKb > 65536 ||
			Number.isNaN(timeCost)     || timeCost < 1     || timeCost > 64 ||
			Number.isNaN(parallelism)  || parallelism < 1  || parallelism > 16 ||
			Math.floor(memoryCostKb / parallelism) < 4
		) {
			return false;
		}
		const VALID_MODES: AuraMode[] = ["hybrid", "independent", "dependent"];
		if (!VALID_MODES.includes(mode)) {
			return false;
		}

		// Pre-check salt and hash lengths before decoding to prevent heap allocation DoS.
		const approxSaltLen = Math.floor((parts[3].length * 3) / 4);
		const approxHashLen = Math.floor((parts[4].length * 3) / 4);
		if (
			approxSaltLen < 8 || approxSaltLen > 64 ||
			approxHashLen < 1 || approxHashLen > 64
		) {
			return false;
		}
		const salt = base64UrlToBytes(parts[3]);
		const expectedHash = base64UrlToBytes(parts[4]);

		const computedHash = await Aura.deriveKey(pwdBytes, salt, {
			memoryCostKb,
			timeCost,
			parallelism,
			mode,
			outputLength: expectedHash.length,
			additionalData: options?.additionalData,
		});

		return constantTimeEqual(expectedHash, computedHash);
	}
}
