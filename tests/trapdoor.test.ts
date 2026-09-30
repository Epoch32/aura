import { describe, expect, it } from "bun:test";
import { Aura } from "../src/core/aura";
import { MemoryDag } from "../src/core/memory-dag";
import { TrapdoorEngine } from "../src/trapdoor/trapdoor";
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

		// Fast O(1) verification with trapdoor key succeeds
		const isKeyedValid = await Aura.verify(password, envelope, trapdoorKey);
		expect(isKeyedValid).toBe(true);

		// Wrong password with correct key is rejected
		const isWrongPwdValid = await Aura.verify(utf8ToBytes("wrong-password"), envelope, trapdoorKey);
		expect(isWrongPwdValid).toBe(false);

		// Unkeyed offline verification is completely blocked (returns false)
		const isUnkeyedBlocked = await Aura.verify(password, envelope);
		expect(isUnkeyedBlocked).toBe(false);
	});

	it("should reject wrong password in masked mode when trapdoor key is provided", async () => {
		// The anchor = HMAC(K, LP(plaintext_dagOutput, salt)).
		// A wrong password produces a different dagOutput, so the anchor check fails.
		const envelope = await Aura.sealWithTrapdoor(password, trapdoorKey, {
			memoryCostKb: 64,
			timeCost: 1,
			mode: "hybrid",
			masked: true,
		});

		const isWrongPwdRejected = await Aura.verify(utf8ToBytes("completely-wrong"), envelope, trapdoorKey);
		expect(isWrongPwdRejected).toBe(false);
	});
});

describe("AURA PHC Version Validation", () => {
	it("should reject PHC strings with a mismatched version field", async () => {
		const hashResult = await Aura.hash("password", { memoryCostKb: 32, timeCost: 1 });
		// Tamper the version to v=99
		const tampered = hashResult.encoded.replace("$v=1$", "$v=99$");
		const isValid = await Aura.verify("password", tampered);
		expect(isValid).toBe(false);
	});
});

describe("MemoryDag Safety Guards", () => {
	it("should throw when execute() is called twice on the same instance", async () => {
		const config = { memoryCostKb: 32, timeCost: 1, parallelism: 1, mode: "hybrid" as const, outputLength: 32 };
		const h0 = await MemoryDag.computeInitialSeed(utf8ToBytes("pwd"), utf8ToBytes("salt"), config);
		const dag = new MemoryDag(config);
		await dag.execute(h0);
		await expect(dag.execute(h0)).rejects.toThrow("already been executed");
	});

	it("should throw when outputLength exceeds 64 bytes", () => {
		expect(() => new MemoryDag({
			memoryCostKb: 32, timeCost: 1, parallelism: 1, mode: "hybrid", outputLength: 65,
		})).toThrow("outputLength must be between 1 and 64");
	});

	it("should throw when outputLength is zero", () => {
		expect(() => new MemoryDag({
			memoryCostKb: 32, timeCost: 1, parallelism: 1, mode: "hybrid", outputLength: 0,
		})).toThrow("outputLength must be between 1 and 64");
	});
});

describe("TrapdoorEngine Key Length Enforcement", () => {
	it("should throw when trapdoorKey is shorter than 16 bytes", async () => {
		const shortKey = new Uint8Array(8);
		const dagOutput = new Uint8Array(32);
		const salt = new Uint8Array(16);
		await expect(TrapdoorEngine.computePublicAnchor(dagOutput, shortKey, salt))
			.rejects.toThrow("at least 16 bytes");
	});

	it("should throw from sealWithTrapdoor when trapdoorKey is too short", async () => {
		await expect(Aura.sealWithTrapdoor("password", new Uint8Array(8), { memoryCostKb: 32, timeCost: 1 }))
			.rejects.toThrow("at least 16 bytes");
	});
});
