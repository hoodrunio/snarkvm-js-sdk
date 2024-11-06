import { Bech32m } from './bech32m';
import { Network } from '../core/types';
import { EncodingError } from '../core/errors';
import { convertToLittleEndian, convertFromLittleEndian } from '../utils/bytes';

export class Encoding {
    // Private Key encoding
    static encodePrivateKey(bytes: Uint8Array, network: Network): string {
        try {
            if (!(bytes instanceof Uint8Array)) {
                throw new EncodingError('Input must be Uint8Array');
            }
            if (bytes.length !== 32) {
                throw new EncodingError('Private key must be 32 bytes');
            }
            if (!network.validateParameters(network.getPrivateKeyPrefix())) {
                throw new EncodingError('Invalid private key prefix');
            }

            const leBytes = convertToLittleEndian(bytes);
            return Bech32m.encode(network.getPrivateKeyPrefix(), leBytes);
        } catch (error) {
            if (error instanceof EncodingError) {
                throw error;
            }
            throw new EncodingError('Failed to encode private key');
        }
    }

    static decodePrivateKey(encoded: string, network: Network): Uint8Array {
        try {
            const { hrp, data } = Bech32m.decode(encoded);
            if (hrp !== network.getPrivateKeyPrefix()) {
                throw new EncodingError(`Invalid private key prefix. Expected ${network.getPrivateKeyPrefix()}`);
            }
            return convertFromLittleEndian(data);
        } catch (error) {
            throw new EncodingError('Invalid private key encoding');
        }
    }

    // View Key encoding
    static encodeViewKey(bytes: Uint8Array, network: Network): string {
        try {
            if (!(bytes instanceof Uint8Array)) {
                throw new EncodingError('Input must be Uint8Array');
            }
            if (bytes.length !== 32) {
                throw new EncodingError('View key must be 32 bytes');
            }
            if (!network.validateParameters(network.getViewKeyPrefix())) {
                throw new EncodingError('Invalid view key prefix');
            }

            const leBytes = convertToLittleEndian(bytes);
            return Bech32m.encode(network.getViewKeyPrefix(), leBytes);
        } catch (error) {
            if (error instanceof EncodingError) {
                throw error;
            }
            throw new EncodingError('Failed to encode view key');
        }
    }

    static decodeViewKey(encoded: string, network: Network): Uint8Array {
        try {
            const { hrp, data } = Bech32m.decode(encoded);
            if (hrp !== network.getViewKeyPrefix()) {
                throw new EncodingError(`Invalid view key prefix. Expected ${network.getViewKeyPrefix()}`);
            }
            return convertFromLittleEndian(data);
        } catch (error) {
            throw new EncodingError('Invalid view key encoding');
        }
    }

    // Compute Key encoding
    static encodeComputeKey(bytes: Uint8Array, network: Network): string {
        try {
            const leBytes = convertToLittleEndian(bytes);
            return Bech32m.encode(network.getComputeKeyPrefix(), leBytes);
        } catch (error) {
            throw new EncodingError('Failed to encode compute key');
        }
    }

    static decodeComputeKey(encoded: string, network: Network): Uint8Array {
        try {
            const { hrp, data } = Bech32m.decode(encoded);
            if (hrp !== network.getComputeKeyPrefix()) {
                throw new EncodingError(`Invalid compute key prefix. Expected ${network.getComputeKeyPrefix()}`);
            }
            return convertFromLittleEndian(data);
        } catch (error) {
            throw new EncodingError('Invalid compute key encoding');
        }
    }

    // Signature encoding
    static encodeSignature(bytes: Uint8Array, network: Network): string {
        try {
            const leBytes = convertToLittleEndian(bytes);
            return Bech32m.encode(network.getSignaturePrefix(), leBytes);
        } catch (error) {
            throw new EncodingError('Failed to encode signature');
        }
    }

    static decodeSignature(encoded: string, network: Network): Uint8Array {
        try {
            const { hrp, data } = Bech32m.decode(encoded);
            if (hrp !== network.getSignaturePrefix()) {
                throw new EncodingError(`Invalid signature prefix. Expected ${network.getSignaturePrefix()}`);
            }
            return convertFromLittleEndian(data);
        } catch (error) {
            throw new EncodingError('Invalid signature encoding');
        }
    }

    // Address encoding
    static encodeAddress(bytes: Uint8Array, network: Network): string {
        try {
            const leBytes = convertToLittleEndian(bytes);
            return Bech32m.encode(network.getAddressPrefix(), leBytes);
        } catch (error) {
            throw new EncodingError('Failed to encode address');
        }
    }

    static decodeAddress(address: string, network: Network): Uint8Array {
        try {
            const { hrp, data } = Bech32m.decode(address);
            if (hrp !== network.getAddressPrefix()) {
                throw new EncodingError(`Invalid address prefix. Expected ${network.getAddressPrefix()}`);
            }
            return convertFromLittleEndian(data);
        } catch (error) {
            throw new EncodingError('Invalid address encoding');
        }
    }
}