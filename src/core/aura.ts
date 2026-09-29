/**
 * AURA (Asymmetric Unkeyed-Resistant Algorithm)
 * Edge-Native Asymmetric Memory-Hard Function & KDF Engine
 * Main High-Level API with Hardened Memory DAG & Asymmetric Vault Masking
 */

import {
	base64UrlToBytes,
	bytesToBase64Url,
	constantTimeEqual,
	randomBytes,
	utf8ToBytes,
} from "../encoding/bytes";
import { AuraMode, MemoryDag, MemoryDagConfig } from "./memory-dag";
import { TrapdoorEngine } from "../trapdoor/trapdoor";

export interface AuraOptions {
	readonly memoryCostKb?: number; // Default: 4096 KB (4 MB)
	readonly timeCost?: number;     // Default: 2 passes
	readonly parallelism?: number;  // Default: 1 lane
	readonly mode?: AuraMode;       // Default: "hybrid" (Argon2id-style)
	readonly outputLength?: number; // Default: 32 bytes
	readonly salt?: Uint8Array;
	readonly additionalData?: Uint8Array;
	readonly masked?: boolean;      // Default: false (enables HKDF vault masking)
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
		const pwdBytes = Aura.toBytes(password);
		const isMasked = options?.masked ?? false;

		// 1. Compute Memory-Hard DAG Output
		const dagOutput = await Aura.deriveKey(pwdBytes, salt, options);

		// 2. Compute Trapdoor Token & Public Anchor
		const trapdoorToken = await TrapdoorEngine.computeTrapdoorToken(trapdoorKey, pwdBytes, salt);
		const publicAnchor = await TrapdoorEngine.computePublicAnchor(dagOutput, trapdoorToken, salt);

		// 3. Optional Vault Masking: dagOutput ^ HKDF(K, salt)
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
		trapdoorKey?: Uint8Array,
	): Promise<boolean> {
		const pwdBytes = Aura.toBytes(password);

		// Case A: Trapdoor Envelope Verification
		if (typeof hashOrEnvelope === "object") {
			const salt = base64UrlToBytes(hashOrEnvelope.salt);
			const publicAnchor = base64UrlToBytes(hashOrEnvelope.publicAnchor);
			const rawDagStored = base64UrlToBytes(hashOrEnvelope.dagOutput);

			// If envelope is masked, offline unkeyed verification is blocked
			if (hashOrEnvelope.masked) {
				if (!trapdoorKey) {
					return false; // Cannot verify masked envelope without trapdoor key
				}
				const unmaskedDag = await TrapdoorEngine.maskDagOutput(rawDagStored, trapdoorKey, salt);
				return TrapdoorEngine.verifyWithTrapdoor(
					pwdBytes,
					salt,
					publicAnchor,
					trapdoorKey,
					unmaskedDag,
				);
			}

			// Fast Path: If trapdoorKey is provided, evaluate in O(1) (< 0.5 ms)
			if (trapdoorKey) {
				return TrapdoorEngine.verifyWithTrapdoor(
					pwdBytes,
					salt,
					publicAnchor,
					trapdoorKey,
					rawDagStored,
				);
			}

			// Slow Path: Recompute Memory DAG without trapdoor key
			const computedDag = await Aura.deriveKey(pwdBytes, salt, {
				memoryCostKb: hashOrEnvelope.memoryCostKb,
				timeCost: hashOrEnvelope.timeCost,
				parallelism: hashOrEnvelope.parallelism,
				mode: hashOrEnvelope.mode,
				outputLength: rawDagStored.length,
			});

			return constantTimeEqual(rawDagStored, computedDag);
		}

		// Case B: Standard PHC Formatted String Verification
		const parts = hashOrEnvelope.split("$").filter(Boolean);
		if (parts.length < 5 || parts[0] !== "aura") {
			return false;
		}

		// Parse params
		const paramStr = parts[2];
		const params = new Map<string, string>();
		for (const kv of paramStr.split(",")) {
			const [k, v] = kv.split("=");
			params.set(k, v);
		}

		const memoryCostKb = Number.parseInt(params.get("m") ?? "4096", 10);
		const timeCost = Number.parseInt(params.get("t") ?? "2", 10);
		const parallelism = Number.parseInt(params.get("p") ?? "1", 10);
		const mode = (params.get("mode") ?? "hybrid") as AuraMode;

		const salt = base64UrlToBytes(parts[3]);
		const expectedHash = base64UrlToBytes(parts[4]);

		const computedHash = await Aura.deriveKey(pwdBytes, salt, {
			memoryCostKb,
			timeCost,
			parallelism,
			mode,
			outputLength: expectedHash.length,
		});

		return constantTimeEqual(expectedHash, computedHash);
	}
}
