import { Scalar } from '../crypto/scalar';
import { HashUtils } from '../crypto/hash';
import { KeyDerivationError } from '../core/errors';
import { encodePrivateKey, decodePrivateKey } from '../crypto/encoding';
import { Network } from '../core/types';
import { AccountObject } from './base';
import { Address } from './address';
import { ViewKey } from './viewKey';
import { ComputeKey } from './computeKey';
import { convertToLittleEndian } from '../utils/bytes';
import { Bech32m } from '../crypto/bech32m';

export class PrivateKey implements AccountObject {
    private readonly scalar: Scalar;

    constructor(scalar: Scalar) {
        if (!scalar) {
            throw new KeyDerivationError('Invalid private key scalar');
        }
        this.scalar = scalar;
    }

    equals(other: AccountObject): boolean {
        if (!(other instanceof PrivateKey)) {
            return false;
        }
        return this.scalar.equals(other.scalar);
    }

    static generate(): PrivateKey {
        const entropy = new Uint8Array(80);
        crypto.getRandomValues(entropy);
        
        const timestamp = BigInt(Date.now()).toString();
        const extraEntropy = Buffer.from(timestamp);
        
        const finalEntropy = Buffer.concat([entropy, extraEntropy]);
        const scalar = HashUtils.hashToScalarPsd8(finalEntropy);
        return new PrivateKey(scalar);
    }

    static fromSeed(seed: Uint8Array): PrivateKey {
        const scalar = HashUtils.hashToScalarPsd8(seed);
        return new PrivateKey(scalar);
    }

    static fromString(encoded: string, network: Network): PrivateKey {
        try {
            const bytes = decodePrivateKey(encoded, network);
            return new PrivateKey(Scalar.fromBytes(bytes));
        } catch (error) {
            throw new KeyDerivationError('Failed to decode private key');
        }
    }

    toAddress(network: Network): Address {
        const viewKey = this.toViewKey(network);
        return viewKey.toAddress(network);
    }

    toViewKey(network: Network): ViewKey {
        try {
            const viewScalar = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    Buffer.from(network.getViewKeyPrefix()),
                    this.scalar.toBytes()
                ])
            );
            return new ViewKey(viewScalar);
        } catch (error) {
            throw new KeyDerivationError('Failed to derive view key');
        }
    }

    toBytes(): Uint8Array {
        return this.scalar.toBytes();
    }

    toString(network: Network): string {
        const leBytes = convertToLittleEndian(this.toBytes());
        return Bech32m.encode(network.getPrivateKeyPrefix(), leBytes);
    }

    toScalar(): Scalar {
        return this.scalar;
    }

    toComputeKey(network: Network): ComputeKey {
        try {
            const skSig = this.scalar;
            const prfSeed = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    Buffer.from(network.getComputeKeyPrefix()),
                    this.scalar.toBytes()
                ])
            );
            return ComputeKey.fromComponents(skSig, prfSeed);
        } catch (error) {
            throw new KeyDerivationError('Failed to derive compute key');
        }
    }
} 