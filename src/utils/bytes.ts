import { Bech32m } from "../crypto/bech32m";

export function convertToLittleEndian(bytes: Uint8Array): Uint8Array {
    if (isLittleEndian()) {
        return bytes;
    }
    return new Uint8Array(bytes).reverse();
}

export function convertFromLittleEndian(bytes: Uint8Array): Uint8Array {
    if (isLittleEndian()) {
        return bytes;
    }
    return new Uint8Array(bytes).reverse();
}

export function isLittleEndian(): boolean {
    const array = new Uint8Array(4);
    new Uint32Array(array.buffer)[0] = 0x12345678;
    return array[0] === 0x78;
}

export function standardizeBytes(bytes: Uint8Array): Uint8Array {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('Input must be Uint8Array');
    }
    return convertToLittleEndian(bytes);
}

export function encodeAny(bytes: Uint8Array, prefix: string): string {
    if (!prefix || typeof prefix !== 'string') {
        throw new TypeError('Invalid prefix');
    }
    const standardBytes = standardizeBytes(bytes);
    return Bech32m.encode(prefix, standardBytes);
}