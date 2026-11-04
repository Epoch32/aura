/**
 * AURA Asymmetric Trapdoor & Vault Masking Engine
 * Enables instant O(1) evaluation for key holders while providing optional Vault Masking
 */
export interface TrapdoorCommitment {
    readonly publicAnchor: Uint8Array;
    readonly salt: Uint8Array;
}
export declare class TrapdoorEngine {
    /**
     * Computes the Public Anchor as HMAC-SHA256(trapdoorKey, LP(dagOutput, salt, password, envelopeMeta))
     *
     * Using HMAC here makes the trapdoor key K cryptographically required to compute or verify
     * the anchor, while binding password, dagOutput, salt, and envelope parameters enables
     * instant O(1) verification (< 0.5 ms) for key holders and authenticates the stored envelope.
     */
    static computePublicAnchor(dagOutput: Uint8Array, trapdoorKey: Uint8Array, salt: Uint8Array, password?: Uint8Array, envelopeMeta?: Uint8Array): Promise<Uint8Array>;
    /**
     * Derives a deterministic mask key stream via HKDF-SHA256
     */
    static deriveMaskKey(trapdoorKey: Uint8Array, salt: Uint8Array, length: number): Promise<Uint8Array>;
    /**
     * Masks or unmasks dagOutput using the derived HKDF keystream
     */
    static maskDagOutput(dagOutput: Uint8Array, trapdoorKey: Uint8Array, salt: Uint8Array): Promise<Uint8Array>;
    /**
     * Instant O(1) Verification using the Trapdoor Key (< 0.5 ms)
     *
     * Recomputes HMAC-SHA256(K, LP(dagOutput, salt, password, envelopeMeta)) and compares
     * to the stored publicAnchor. Because K is the HMAC key, this check is impossible without K.
     */
    static verifyWithTrapdoor(dagOutput: Uint8Array, salt: Uint8Array, publicAnchor: Uint8Array, trapdoorKey: Uint8Array, password?: Uint8Array, envelopeMeta?: Uint8Array): Promise<boolean>;
}
