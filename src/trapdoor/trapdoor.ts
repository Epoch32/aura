/**
 * AURA Asymmetric Trapdoor & Vault Masking Engine
 * Enables instant O(1) evaluation for key holders while providing optional Vault Masking
 */

import { constantTimeEqual, encodeLengthPrefixed } from "../encoding/bytes";

export interface TrapdoorCommitment {
	readonly publicAnchor: Uint8Array;
	readonly salt: Uint8Array;
}

export class TrapdoorEngine {
	/**
	 * Computes the Public Anchor as HMAC-SHA256(trapdoorKey, LP(dagOutput) || LP(salt))
	 *
	 * Using HMAC here (rather than SHA-256) makes the trapdoor key K cryptographically
	 * required to compute or verify the anchor. An attacker with the stored dagOutput
	 * cannot check candidate passwords against the anchor without possessing K.
	 *
	 * Inputs are length-prefix encoded to prevent ambiguous-concatenation attacks.
	 */
	static async computePublicAnchor(
		dagOutput: Uint8Array,
		trapdoorKey: Uint8Array,
		salt: Uint8Array,
	): Promise<Uint8Array> {
		if (trapdoorKey.length < 16) {
			throw new Error("trapdoorKey must be at least 16 bytes (128 bits); use 32 bytes (256 bits) for full security");
		}
		const key = await crypto.subtle.importKey(
			"raw",
			trapdoorKey as unknown as BufferSource,
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);

		// Length-prefix encoding prevents pwd="abc",salt="defg" from colliding with
		// pwd="abcd",salt="efg" in the HMAC input stream.
		const data = encodeLengthPrefixed(dagOutput, salt);
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
		if (trapdoorKey.length < 16) {
			throw new Error("trapdoorKey must be at least 16 bytes (128 bits); use 32 bytes (256 bits) for full security");
		}
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
	 * Instant O(1) Verification using the Trapdoor Key (< 0.5 ms)
	 *
	 * Recomputes HMAC-SHA256(K, LP(dagOutput) || LP(salt)) and compares to the stored
	 * publicAnchor. Because K is the HMAC key, this check is impossible without K.
	 */
	static async verifyWithTrapdoor(
		dagOutput: Uint8Array,
		salt: Uint8Array,
		publicAnchor: Uint8Array,
		trapdoorKey: Uint8Array,
	): Promise<boolean> {
		const expectedAnchor = await TrapdoorEngine.computePublicAnchor(dagOutput, trapdoorKey, salt);
		return constantTimeEqual(publicAnchor, expectedAnchor);
	}
}
