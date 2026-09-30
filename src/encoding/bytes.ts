/**
 * Zero-dependency Byte & Encoding Utilities for AURA
 */

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
	let totalLength = 0;
	for (let i = 0; i < arrays.length; i++) {
		totalLength += arrays[i].length;
	}
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (let i = 0; i < arrays.length; i++) {
		result.set(arrays[i], offset);
		offset += arrays[i].length;
	}
	return result;
}

export function bytesToHex(bytes: Uint8Array): string {
	let hex = "";
	for (let i = 0; i < bytes.length; i++) {
		hex += bytes[i].toString(16).padStart(2, "0");
	}
	return hex;
}

export function hexToBytes(hex: string): Uint8Array {
	const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
	if (cleaned.length % 2 !== 0) {
		throw new Error(`Invalid hex string length: ${cleaned.length}`);
	}
	if (cleaned.length > 0 && !/^[0-9a-fA-F]+$/.test(cleaned)) {
		throw new Error("Invalid hex string: contains non-hex characters");
	}
	const bytes = new Uint8Array(cleaned.length / 2);
	for (let i = 0; i < cleaned.length; i += 2) {
		bytes[i / 2] = Number.parseInt(cleaned.substring(i, i + 2), 16);
	}
	return bytes;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	// Avoid early exit on length mismatch — iterate the full max-length loop
	// so the running time does not reveal the expected hash length to a timing attacker.
	const maxLen = Math.max(a.length, b.length);
	let diff = a.length ^ b.length; // non-zero if lengths differ
	for (let i = 0; i < maxLen; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}
	return diff === 0;
}

/**
 * Encodes multiple byte arrays with a uint32LE length prefix each before concatenating.
 * Prevents ambiguous-prefix attacks on HMAC inputs where variable-length fields are joined.
 *   e.g. pwd="abc", salt="defg"  vs  pwd="abcd", salt="efg"  → same raw concat, different LP encoding
 */
export function encodeLengthPrefixed(...arrays: Uint8Array[]): Uint8Array {
	let totalLength = 0;
	for (const arr of arrays) {
		totalLength += 4 + arr.length; // 4-byte prefix per array
	}
	const result = new Uint8Array(totalLength);
	const view = new DataView(result.buffer);
	let offset = 0;
	for (const arr of arrays) {
		view.setUint32(offset, arr.length, true);
		offset += 4;
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

export function randomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return bytes;
}

export function utf8ToBytes(str: string): Uint8Array {
	return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes: Uint8Array): string {
	return new TextDecoder().decode(bytes);
}

export function bytesToBigIntLE(bytes: Uint8Array): bigint {
	let result = 0n;
	for (let i = bytes.length - 1; i >= 0; i--) {
		result = (result << 8n) | BigInt(bytes[i]);
	}
	return result;
}

export function bigIntToBytesLE(n: bigint, length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	let temp = n;
	for (let i = 0; i < length; i++) {
		bytes[i] = Number(temp & 0xffn);
		temp >>= 8n;
	}
	return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export function base64UrlToBytes(base64url: string): Uint8Array {
	// Validate input uses only the base64url alphabet (A-Z, a-z, 0-9, -, _).
	// atob() silently ignores whitespace and some illegal characters per the HTML spec;
	// we reject them explicitly to stay consistent with hexToBytes's strict contract.
	if (base64url.length > 0 && !/^[A-Za-z0-9\-_]+$/.test(base64url)) {
		throw new Error("Invalid base64url string: contains illegal characters");
	}
	let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
	while (base64.length % 4 !== 0) {
		base64 += "=";
	}
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}
