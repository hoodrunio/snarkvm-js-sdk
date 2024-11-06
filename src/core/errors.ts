export class AleoError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = 'AleoError';
    }
}

export class AddressError extends AleoError {
    constructor(message: string) {
        super(message, 'ADDRESS_ERROR');
    }
}

export class KeyDerivationError extends AleoError {
    constructor(message: string) {
        super(message, 'KEY_DERIVATION_ERROR');
    }
}

export class CacheError extends AleoError {
    constructor(message: string) {
        super(message, 'CACHE_ERROR');
    }
}

export class HashError extends AleoError {
    constructor(message: string) {
        super(message, 'HASH_ERROR');
    }
}

export class EncodingError extends AleoError {
    constructor(message: string) {
        super(message, 'ENCODING_ERROR');
    }
}

export class CryptoError extends AleoError {
    constructor(message: string) {
        super(message, 'CRYPTO_ERROR');
    }
}

export class SignatureError extends AleoError {
    constructor(message: string) {
        super(message, 'SIGNATURE_ERROR');
    }
}