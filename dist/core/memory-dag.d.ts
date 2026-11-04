/**
 * AURA Memory DAG (Directed Acyclic Graph) Execution Engine
 * Supports Hybrid (Argon2id-style), Data-Independent, and Data-Dependent Modes
 * Hardened with Non-Uniform Quadratic Indexing (TMTO Defense) & ARX Address Expansion
 */
export type AuraMode = "hybrid" | "independent" | "dependent";
export interface MemoryDagConfig {
    readonly memoryCostKb: number;
    readonly timeCost: number;
    readonly parallelism: number;
    readonly mode: AuraMode;
    readonly outputLength: number;
}
export declare class MemoryDag {
    readonly config: MemoryDagConfig;
    readonly totalBlocks: number;
    readonly blocksPerLane: number;
    private memoryBuffer;
    private blocks;
    private addrBlock;
    private cachedAddrPass;
    private cachedAddrLane;
    private cachedAddrSegment;
    private executed;
    static validateConfig(config: MemoryDagConfig): void;
    constructor(config: MemoryDagConfig);
    private getBlock;
    /**
     * Computes initial 64-byte seed H0
     */
    static computeInitialSeed(password: Uint8Array, salt: Uint8Array, config: MemoryDagConfig, additionalData?: Uint8Array): Promise<Uint8Array>;
    /**
     * Initializes Block 0 and Block 1 for each lane using H0
     */
    initializeFirstBlocks(h0: Uint8Array): Promise<void>;
    private static readonly SYNC_POINTS;
    private getSliceBounds;
    private getSliceForIndex;
    /**
     * Computes the reference block index j and lane using Quadratic Non-Uniform Mapping (TMTO Defense)
     * and Argon2-style 4-slice cross-lane synchronization.
     */
    private computeReferenceIndex;
    /**
     * Executes the full multi-pass memory mixing graph across synchronized slices
     */
    execute(h0: Uint8Array): Promise<Uint8Array>;
}
