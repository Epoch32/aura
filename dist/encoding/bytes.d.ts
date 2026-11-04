/**
 * Zero-dependency Byte & Encoding Utilities for AURA
 */
export declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
/**
 * Encodes multiple byte arrays with a uint32LE length prefix each before concatenating.
 * Prevents ambiguous-prefix attacks on HMAC inputs where variable-length fields are joined.
 *   e.g. pwd="abc", salt="defg"  vs  pwd="abcd", salt="efg"  → same raw concat, different LP encoding
 */
export declare function encodeLengthPrefixed(...arrays: Uint8Array[]): Uint8Array;
export declare function randomBytes(length: number): Uint8Array;
export declare function utf8ToBytes(str: string): Uint8Array;
export declare function bytesToUtf8(bytes: Uint8Array): string;
export declare function bytesToBigIntLE(bytes: Uint8Array): bigint;
export declare function bigIntToBytesLE(n: bigint, length: number): Uint8Array;
export declare function bytesToBase64Url(bytes: Uint8Array): string;
export declare function base64UrlToBytes(base64url: string): Uint8Array;
