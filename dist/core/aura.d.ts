/**
 * AURA (Asymmetric Unkeyed-Resistant Algorithm)
 * Edge-Native Asymmetric Memory-Hard Function & KDF Engine
 * Main High-Level API with Hardened Memory DAG & Asymmetric Vault Masking
 */
import { AuraMode, MemoryDagConfig } from "./memory-dag";
export interface AuraVerifyOptions {
    readonly additionalData?: Uint8Array;
}
export interface AuraOptions {
    readonly memoryCostKb?: number;
    readonly timeCost?: number;
    readonly parallelism?: number;
    readonly mode?: AuraMode;
    readonly outputLength?: number;
    readonly salt?: Uint8Array;
    readonly additionalData?: Uint8Array;
    readonly masked?: boolean;
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
    readonly salt: string;
    readonly publicAnchor: string;
    readonly dagOutput: string;
}
export declare class Aura {
    static readonly VERSION = 1;
    static readonly DEFAULT_CONFIG: MemoryDagConfig;
    /**
     * Resolves options with default values
     */
    private static resolveConfig;
    private static toBytes;
    /**
     * Derives raw key material using the memory-hard graph
     */
    static deriveKey(password: string | Uint8Array, salt: Uint8Array, options?: AuraOptions): Promise<Uint8Array>;
    /**
     * Hashes a password into a standard PHC-formatted AURA string
     * Format: $aura$v=1$m=4096,t=2,p=1,mode=hybrid$salt$hash
     */
    static hash(password: string | Uint8Array, options?: AuraOptions): Promise<AuraHashResult>;
    private static encodeEnvelopeMeta;
    /**
     * Seals a secret with an Asymmetric Trapdoor Key
     * If options.masked = true, encrypts dagOutput under K so offline dictionary searches are impossible.
     */
    static sealWithTrapdoor(password: string | Uint8Array, trapdoorKey: Uint8Array, options?: AuraOptions): Promise<AuraSealedEnvelope>;
    /**
     * Verifies a password against a standard PHC hash or Trapdoor Sealed Envelope
     */
    static verify(password: string | Uint8Array, hashOrEnvelope: string | AuraSealedEnvelope, trapdoorKeyOrOptions?: Uint8Array | AuraVerifyOptions, options?: AuraVerifyOptions): Promise<boolean>;
    private static _verify;
}
