import { describe, expect, it } from "bun:test";
import { Aura } from "../src/core/aura";
import { utf8ToBytes } from "../src/encoding/bytes";

describe("AURA High-Level API", () => {
	const password = "my-secret-passphrase";

	it("should hash and verify password with PHC format", async () => {
		const hashResult = await Aura.hash(password, {
			memoryCostKb: 64,
			timeCost: 1,
			mode: "hybrid",
		});

		expect(hashResult.encoded.startsWith("$aura$v=1$")).toBe(true);
		expect(hashResult.rawHash.length).toBe(32);

		// Valid password verification
		const isValid = await Aura.verify(password, hashResult.encoded);
		expect(isValid).toBe(true);

		// Invalid password verification
		const isInvalid = await Aura.verify("incorrect-passphrase", hashResult.encoded);
		expect(isInvalid).toBe(false);
	});

	it("should derive keys of customizable length", async () => {
		const salt = utf8ToBytes("test-salt-42");
		const key32 = await Aura.deriveKey(password, salt, {
			memoryCostKb: 32,
			timeCost: 1,
			outputLength: 32,
		});
		const key64 = await Aura.deriveKey(password, salt, {
			memoryCostKb: 32,
			timeCost: 1,
			outputLength: 64,
		});

		expect(key32.length).toBe(32);
		expect(key64.length).toBe(64);
		// Output length is part of domain separation header
		expect(key32).not.toEqual(key64.slice(0, 32));
	});
});
