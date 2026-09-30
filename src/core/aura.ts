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
		if (salt.length < 8) {
			throw new Error("Salt must be at least 8 bytes; 16 bytes (128 bits) is recommended");
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
		if (salt.length < 8) {
			throw new Error("Salt must be at least 8 bytes; 16 bytes (128 bits) is recommended");
		}
		const pwdBytes = Aura.toBytes(password);
		const isMasked = options?.masked ?? true;

		// 1. Compute Memory-Hard DAG Output
		const dagOutput = await Aura.deriveKey(pwdBytes, salt, options);

		// 2. Compute Public Anchor: HMAC-SHA256(K, LP(dagOutput, salt))
		//    The anchor always commits to the *plaintext* dagOutput so that password
		//    verification requires re-deriving MHF(candidate) and checking the anchor.
		//    K is the HMAC key — an attacker without K cannot compute or verify the anchor.
		const publicAnchor = await TrapdoorEngine.computePublicAnchor(dagOutput, trapdoorKey, salt);

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
		trapdoorKey?: Uint8Array,
	): Promise<boolean> {
		try {
			return await Aura._verify(password, hashOrEnvelope, trapdoorKey);
		} catch {
			return false;
		}
	}

	private static async _verify(
		password: string | Uint8Array,
		hashOrEnvelope: string | AuraSealedEnvelope,
		trapdoorKey?: Uint8Array,
	): Promise<boolean> {
		const pwdBytes = Aura.toBytes(password);

		// Case A: Trapdoor Envelope Verification
		if (typeof hashOrEnvelope === "object") {
			const salt = base64UrlToBytes(hashOrEnvelope.salt);
			const publicAnchor = base64UrlToBytes(hashOrEnvelope.publicAnchor);
			// Guard against oversized dagOutput blobs: check the approximate decoded length
			// before allocating, since MemoryDag caps outputLength at 64 bytes.
			const approxDecodedLen = Math.floor(hashOrEnvelope.dagOutput.length * 3 / 4);
			if (approxDecodedLen < 1 || approxDecodedLen > 64) {
				return false;
			}
			const rawDagStored = base64UrlToBytes(hashOrEnvelope.dagOutput);
			const dagOptions = {
				memoryCostKb: hashOrEnvelope.memoryCostKb,
				timeCost: hashOrEnvelope.timeCost,
				parallelism: hashOrEnvelope.parallelism,
				mode: hashOrEnvelope.mode,
				outputLength: rawDagStored.length,
			};

			// Masked Vault Mode: dagOutput is blinded under K.
			// The anchor commits to the *plaintext* dagOutput, so we must re-derive the
			// candidate DAG from the submitted password and check it against the anchor.
			// Without K the attacker cannot check the anchor, and without the plaintext
			// dagOutput they cannot compare directly — offline attacks are blocked.
			if (hashOrEnvelope.masked) {
				if (!trapdoorKey) {
					return false; // Cannot verify masked envelope without trapdoor key
				}
				const candidateDag = await Aura.deriveKey(pwdBytes, salt, dagOptions);
				return TrapdoorEngine.verifyWithTrapdoor(candidateDag, salt, publicAnchor, trapdoorKey);
			}

			// Unmasked + trapdoor key: the anchor commits to the plaintext dagOutput stored in
			// the envelope, so we must re-derive the candidate DAG and verify via HMAC.
			if (trapdoorKey) {
				const candidateDag = await Aura.deriveKey(pwdBytes, salt, dagOptions);
				return TrapdoorEngine.verifyWithTrapdoor(candidateDag, salt, publicAnchor, trapdoorKey);
			}

			// Slow Path (no trapdoor key): compare dagOutput directly.
			// The anchor is HMAC-protected and cannot be verified without K.
			const computedDag = await Aura.deriveKey(pwdBytes, salt, dagOptions);
			return constantTimeEqual(rawDagStored, computedDag);
		}

		// Case B: Standard PHC Formatted String Verification
		const parts = hashOrEnvelope.split("$").filter(Boolean);
		if (parts.length < 5 || parts[0] !== "aura") {
			return false;
		}

		// Validate version — reject hashes from unknown future versions
		if (parts[1] !== `v=${Aura.VERSION}`) {
			return false;
		}

		// Parse params — reject duplicate keys to prevent parameter injection attacks.
		// e.g. "m=4096,...,m=64" must not silently downgrade memory cost to 64 KB.
		const paramStr = parts[2];
		const params = new Map<string, string>();
		for (const kv of paramStr.split(",")) {
			const [k, v] = kv.split("=");
			if (params.has(k)) {
				return false; // duplicate key — reject as malformed / tampered
			}
			params.set(k, v);
		}

		const memoryCostKb = Number.parseInt(params.get("m") ?? "4096", 10);
		const timeCost = Number.parseInt(params.get("t") ?? "2", 10);
		const parallelism = Number.parseInt(params.get("p") ?? "1", 10);
		const mode = (params.get("mode") ?? "hybrid") as AuraMode;

		// Validate parameter ranges — prevents DoS via enormous memory allocation or
		// unbounded computation, and rejects unknown mode strings that would silently
		// fall through to data-dependent indexing.
		if (
			Number.isNaN(memoryCostKb) || memoryCostKb < 8 || memoryCostKb > 65536 ||
			Number.isNaN(timeCost)     || timeCost < 1     || timeCost > 64 ||
			Number.isNaN(parallelism)  || parallelism < 1  || parallelism > 16
		) {
			return false;
		}
		const VALID_MODES: AuraMode[] = ["hybrid", "independent", "dependent"];
		if (!VALID_MODES.includes(mode)) {
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
		});

		return constantTimeEqual(expectedHash, computedHash);
	}
}
