import { describe, expect, it } from "bun:test";
import { MemoryDag, MemoryDagConfig } from "../src/core/memory-dag";
import { utf8ToBytes } from "../src/encoding/bytes";

describe("AURA Memory DAG", () => {
	const password = utf8ToBytes("correct horse battery staple");
	const salt = utf8ToBytes("random-salt-1234");

	it("should execute Hybrid Mode deterministically", async () => {
		const config: MemoryDagConfig = {
			memoryCostKb: 64, // 64 KB for fast test execution
			timeCost: 1,
			parallelism: 1,
			mode: "hybrid",
			outputLength: 32,
		};

		const h0_1 = await MemoryDag.computeInitialSeed(password, salt, config);
		const h0_2 = await MemoryDag.computeInitialSeed(password, salt, config);

		const dag1 = new MemoryDag(config);
		const dag2 = new MemoryDag(config);

		const out1 = await dag1.execute(h0_1);
		const out2 = await dag2.execute(h0_2);

		expect(out1.length).toBe(32);
		expect(out1).toEqual(out2);
	});

	it("should produce different outputs for different modes", async () => {
		const baseConfig = {
			memoryCostKb: 32,
			timeCost: 1,
			parallelism: 1,
			outputLength: 32,
		};

		const hybridCfg = { ...baseConfig, mode: "hybrid" as const };
		const independentCfg = { ...baseConfig, mode: "independent" as const };
		const dependentCfg = { ...baseConfig, mode: "dependent" as const };

		const h0_h = await MemoryDag.computeInitialSeed(password, salt, hybridCfg);
		const h0_i = await MemoryDag.computeInitialSeed(password, salt, independentCfg);
		const h0_d = await MemoryDag.computeInitialSeed(password, salt, dependentCfg);

		const outH = await new MemoryDag(hybridCfg).execute(h0_h);
		const outI = await new MemoryDag(independentCfg).execute(h0_i);
		const outD = await new MemoryDag(dependentCfg).execute(h0_d);

		expect(outH).not.toEqual(outI);
		expect(outH).not.toEqual(outD);
	});

	it("should execute across multiple parallelism lanes", async () => {
		const multiLaneCfg: MemoryDagConfig = {
			memoryCostKb: 64,
			timeCost: 1,
			parallelism: 2,
			mode: "hybrid",
			outputLength: 32,
		};

		const h0 = await MemoryDag.computeInitialSeed(password, salt, multiLaneCfg);
		const dag = new MemoryDag(multiLaneCfg);
		const out = await dag.execute(h0);

		expect(out.length).toBe(32);
	});

	it("should never select prevBlock or currentBlock as refBlock across passes", async () => {
		const config: MemoryDagConfig = {
			memoryCostKb: 64,
			timeCost: 2,
			parallelism: 1,
			mode: "hybrid",
			outputLength: 32,
		};

		const h0 = await MemoryDag.computeInitialSeed(password, salt, config);
		const dag = new MemoryDag(config);

		// Intercept computeReferenceIndex to verify no collisions with i or prevIdx
		const origCompute = dag["computeReferenceIndex"].bind(dag);
		let checkedLookups = 0;
		dag["computeReferenceIndex"] = function (pass: number, lane: number, i: number, prevBlock: Uint32Array) {
			const res = origCompute(pass, lane, i, prevBlock);
			const prevIdx = i === 0 ? dag.blocksPerLane - 1 : i - 1;
			expect(res.refIndex).not.toBe(i);
			expect(res.refIndex).not.toBe(prevIdx);
			checkedLookups++;
			return res;
		};

		await dag.execute(h0);
		expect(checkedLookups).toBeGreaterThan(50);
	});
});
