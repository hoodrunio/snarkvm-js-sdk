import { Scalar } from '../crypto/scalar';
import { Group } from '../crypto/group';
import { HashUtils } from '../crypto/hash';
import { PrivateKey } from './privateKey';
import { Address } from './address';
import { Network } from '../core/types';
import { CryptoError, KeyDerivationError } from '../core/errors';
import { AccountObject } from './base';
import { decodeViewKey } from '../crypto/encoding';
import { Bech32m } from '../crypto/bech32m';
import { convertToLittleEndian } from '../utils/bytes';
export class ViewKey implements AccountObject {
    private readonly scalar: Scalar;

    constructor(scalar: Scalar) {
        if (!scalar) {
            throw new KeyDerivationError('Invalid view key scalar');
        }
        this.scalar = scalar;
    }

    static fromPrivateKey(privateKey: PrivateKey, network: Network): ViewKey {
        try {
            const viewScalar = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    privateKey.toBytes(),
                    Buffer.from([HashUtils.DOMAIN_SEPARATORS.VIEW_KEY]),
                    Buffer.from(network.getViewKeyPrefix())
                ]),
                'VIEW_KEY'
            );
            return new ViewKey(viewScalar);
        } catch (error) {
            throw new KeyDerivationError('Failed to derive view key');
        }
    }

    static fromString(viewKeyString: string, network: Network): ViewKey {
        try {
            const decoded = decodeViewKey(viewKeyString, network);
            return new ViewKey(Scalar.fromBytes(decoded));
        } catch (error) {
            throw new KeyDerivationError('Invalid view key string');
        }
    }

    toAddress(network: Network): Address {
        try {
            const addressScalar = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    Buffer.from(network.getAddressPrefix()),
                    this.scalar.toBytes()
                ]),
                'ADDRESS'
            );
            
            if (!addressScalar) {
                throw new KeyDerivationError('Invalid address scalar');
            }
            
            const addressGroup = Group.BASE_POINT.multiply(addressScalar);
            return new Address(addressGroup);
        } catch (error) {
            if (error instanceof CryptoError) {
                throw error;
            }
            throw new KeyDerivationError('Failed to derive address from view key');
        }
    }

    toBytes(): Uint8Array {
        return this.scalar.toBytes();
    }

    toString(network: Network): string {
        try {
            const bytes = this.toBytes();
            return Bech32m.encode(network.getViewKeyPrefix(), convertToLittleEndian(bytes));
        } catch (error) {
            throw new KeyDerivationError('Failed to encode view key');
        }
    }

    decrypt(ciphertext: Uint8Array): Uint8Array {
        try {
            if (ciphertext.length <= 32) {
                throw new KeyDerivationError('Invalid ciphertext length');
            }

            const key = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    this.scalar.toBytes(),
                    ciphertext.slice(0, 32)
                ]),
                'DECRYPT'
            );
            
            const message = new Uint8Array(ciphertext.length - 32);
            for (let i = 0; i < message.length; i++) {
                message[i] = ciphertext[i + 32] ^ key.toBytes()[i % 32];
            }
            
            return message;
        } catch (error) {
            if (error instanceof KeyDerivationError) {
                throw error;
            }
            throw new KeyDerivationError('Failed to decrypt message');
        }
    }

    equals(other: ViewKey): boolean {
        return this.scalar.equals(other.scalar);
    }
} 