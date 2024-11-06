import { randomBytes } from 'crypto';
import BN from 'bn.js';
import { ICryptoScalar, RawScalar } from '../core/types';
import { CryptoError } from '../core/errors';

export class Scalar implements ICryptoScalar {
    private value: BN;
    
    private static readonly GROUP_ORDER = new BN(
        '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
        16
    );

    constructor(value: BN) {
        if (!value) {
            throw new CryptoError('Invalid scalar value');
        }
        this.value = value.umod(Scalar.GROUP_ORDER);
    }

    static random(): Scalar {
        let attempts = 0;
        const maxAttempts = 100;

        while (attempts < maxAttempts) {
            const bytes = randomBytes(32);
            const value = new BN(bytes);
            
            if (value.lt(Scalar.GROUP_ORDER)) {
                return new Scalar(value);
            }
            attempts++;
        }

        throw new CryptoError('Failed to generate random scalar');
    }

    add(other: Scalar): Scalar {
        return new Scalar(this.value.add(other.value));
    }

    mul(other: Scalar): Scalar {
        return new Scalar(this.value.mul(other.value));
    }

    multiply(other: Scalar): Scalar {
        return new Scalar(this.value.mul(other.value).umod(Scalar.GROUP_ORDER));
    }

    negate(): Scalar {
        return new Scalar(this.value.neg());
    }

    equals(other: Scalar): boolean {
        return this.value.eq(other.value);
    }

    toRawBytes(): RawScalar {
        const bytes = this.toBytes();
        return new Uint8Array(bytes);
    }
    toBigInt(): bigint {
        return BigInt(this.value.toString());
    }

    toBytes(): Uint8Array {
        return new Uint8Array(this.value.toArray('be', 32));
    }

    toString(): string {
        return this.value.toString(16).padStart(64, '0');
    }

    static fromBytes(bytes: Uint8Array): Scalar {
        if (!(bytes instanceof Uint8Array)) {
            throw new CryptoError('Input must be Uint8Array');
        }
        if (bytes.length !== 32) {
            throw new CryptoError('Input must be 32 bytes');
        }
        return new Scalar(new BN(bytes));
    }
} 