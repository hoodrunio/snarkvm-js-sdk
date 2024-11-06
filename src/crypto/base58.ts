import bs58 from 'bs58';

export function encode(data: Uint8Array): string {
    return bs58.encode(data);
}

export function decode(str: string): Uint8Array {
    return bs58.decode(str);
} 