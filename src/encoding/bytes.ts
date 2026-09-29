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
	const bytes = new Uint8Array(cleaned.length / 2);
	for (let i = 0; i < cleaned.length; i += 2) {
		bytes[i / 2] = Number.parseInt(cleaned.substring(i, i + 2), 16);
	}
	return bytes;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
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
