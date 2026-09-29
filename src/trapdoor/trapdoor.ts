/**
 * AURA Asymmetric Trapdoor & Vault Masking Engine
 * Enables instant O(1) evaluation for key holders while providing optional Vault Masking
 */

import { concatBytes, constantTimeEqual } from "../encoding/bytes";

export interface TrapdoorCommitment {
	readonly publicAnchor: Uint8Array;
	readonly salt: Uint8Array;
}

export class TrapdoorEngine {
	/**
	 * Computes the Trapdoor Secret Token T = HMAC-SHA256(trapdoorKey, password || salt)
	 */
	static async computeTrapdoorToken(
		trapdoorKey: Uint8Array,
		password: Uint8Array,
		salt: Uint8Array,
	): Promise<Uint8Array> {
		const key = await crypto.subtle.importKey(
			"raw",
			trapdoorKey as unknown as BufferSource,
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);

		const data = concatBytes(password, salt);
		const signature = await crypto.subtle.sign("HMAC", key, data as unknown as BufferSource);
		return new Uint8Array(signature);
	}

	/**
	 * Derives a deterministic mask key stream via HKDF-SHA256
	 */
	static async deriveMaskKey(
		trapdoorKey: Uint8Array,
		salt: Uint8Array,
		length: number,
	): Promise<Uint8Array> {
		const baseKey = await crypto.subtle.importKey(
			"raw",
			trapdoorKey as unknown as BufferSource,
			"HKDF",
			false,
			["deriveBits"],
		);

		const derivedBits = await crypto.subtle.deriveBits(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: salt as unknown as BufferSource,
				info: new TextEncoder().encode("aura:vault:mask") as unknown as BufferSource,
			},
			baseKey,
			length * 8,
		);

		return new Uint8Array(derivedBits);
	}

	/**
	 * Masks or unmasks dagOutput using the derived HKDF keystream
	 */
	static async maskDagOutput(
		dagOutput: Uint8Array,
		trapdoorKey: Uint8Array,
		salt: Uint8Array,
	): Promise<Uint8Array> {
		const mask = await TrapdoorEngine.deriveMaskKey(trapdoorKey, salt, dagOutput.length);
		const masked = new Uint8Array(dagOutput.length);
		for (let i = 0; i < dagOutput.length; i++) {
			masked[i] = dagOutput[i] ^ mask[i];
		}
		return masked;
	}

	/**
	 * Binds the memory-hard DAG output with the Trapdoor Token into a Public Anchor
	 * Anchor = SHA-256( dagOutput || TrapdoorToken || salt )
	 */
	static async computePublicAnchor(
		dagOutput: Uint8Array,
		trapdoorToken: Uint8Array,
		salt: Uint8Array,
	): Promise<Uint8Array> {
		const payload = concatBytes(dagOutput, trapdoorToken, salt);
		const hash = await crypto.subtle.digest("SHA-256", payload as unknown as BufferSource);
		return new Uint8Array(hash);
	}

	/**
	 * Instant O(1) Verification using the Trapdoor Key (< 0.5 ms)
	 */
	static async verifyWithTrapdoor(
		password: Uint8Array,
		salt: Uint8Array,
		publicAnchor: Uint8Array,
		trapdoorKey: Uint8Array,
		dagOutput: Uint8Array,
	): Promise<boolean> {
		const token = await TrapdoorEngine.computeTrapdoorToken(trapdoorKey, password, salt);
		const expectedAnchor = await TrapdoorEngine.computePublicAnchor(dagOutput, token, salt);
		return constantTimeEqual(publicAnchor, expectedAnchor);
	}
}
