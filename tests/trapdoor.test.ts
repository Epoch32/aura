import { describe, expect, it } from "bun:test";
import { Aura } from "../src/core/aura";
import { randomBytes, utf8ToBytes } from "../src/encoding/bytes";

describe("AURA Asymmetric Trapdoor", () => {
	const password = utf8ToBytes("super-secure-passkey-vault-seed");
	const trapdoorKey = randomBytes(32);

	it("should instantly verify via trapdoor shortcut", async () => {
		const envelope = await Aura.sealWithTrapdoor(password, trapdoorKey, {
			memoryCostKb: 64,
			timeCost: 1,
			mode: "hybrid",
		});

		// Fast verification with trapdoor key
		const isFastValid = await Aura.verify(password, envelope, trapdoorKey);
		expect(isFastValid).toBe(true);

		// Rejection on wrong password with trapdoor key
		const isWrongPwdValid = await Aura.verify(utf8ToBytes("wrong-password"), envelope, trapdoorKey);
		expect(isWrongPwdValid).toBe(false);

		// Rejection on wrong trapdoor key
		const wrongKey = randomBytes(32);
		const isWrongKeyValid = await Aura.verify(password, envelope, wrongKey);
		expect(isWrongKeyValid).toBe(false);
	});

	it("should verify via slow memory-hard DAG fallback when trapdoor key is omitted", async () => {
		const envelope = await Aura.sealWithTrapdoor(password, trapdoorKey, {
			memoryCostKb: 64,
			timeCost: 1,
			mode: "hybrid",
		});

		// Unkeyed verification (falls back to memory DAG evaluation)
		const isDagValid = await Aura.verify(password, envelope);
		expect(isDagValid).toBe(true);

		// Rejection on wrong password via DAG
		const isWrongDagValid = await Aura.verify(utf8ToBytes("wrong-pwd"), envelope);
		expect(isWrongDagValid).toBe(false);
	});

	it("should support Masked Vault Mode protecting dagOutput from offline dictionary search", async () => {
		const envelope = await Aura.sealWithTrapdoor(password, trapdoorKey, {
			memoryCostKb: 64,
			timeCost: 1,
			mode: "hybrid",
			masked: true,
		});

		expect(envelope.masked).toBe(true);

		// Fast verification with trapdoor key succeeds
		const isKeyedValid = await Aura.verify(password, envelope, trapdoorKey);
		expect(isKeyedValid).toBe(true);

		// Unkeyed offline verification is completely blocked (returns false)
		const isUnkeyedBlocked = await Aura.verify(password, envelope);
		expect(isUnkeyedBlocked).toBe(false);
	});
});
