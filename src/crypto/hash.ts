import { sha512 } from '@noble/hashes/sha512';
import { Scalar } from './scalar';
import { Group } from './group';
import { HashError } from '../core/errors';

export class HashUtils {
    public static readonly DOMAIN_SEPARATORS = {
        PRIVATE_KEY: 0x01,
        VIEW_KEY: 0x02,
        ADDRESS: 0x03,
        SIGNATURE: 0x04,
        COMPUTE_KEY: 0x05,
        PRF_SEED: 0x06,
        CHALLENGE: 0x07,
        PSD8: 0x08,
        RECORD: 0x09,
        COMMITMENT: 0x0A,
        ENCRYPTION: 0x0B,
        TRANSITION: 0x0C,
        CONSTRAINT: 0x0D,
        PRF_EXPAND: 0x0E,
        PROOF: 0x0F,
        TRANSITION_ID: 0x10,
        PROGRAM_ID: 0x11,
        FUNCTION_ID: 0x12,
        CONSTRAINT_ID: 0x13,
        RECORD_COMMITMENT: 0x14,
        RECORD_NONCE: 0x15,
        RECORD_PLAINTEXT: 0x16,
        RECORD_CIPHERTEXT: 0x17
    } as const;

    private static readonly MAX_HASH_ATTEMPTS = 256;

    /**
     * Hashes input bytes to a scalar using PSD8 domain separation
     * @param input - Input bytes to hash
     * @param operation - Operation for domain separation
     * @returns Scalar value derived from hash
     * @throws HashError if input validation fails or hash output is invalid
     */
    static hashToScalarPsd8(input: Uint8Array, operation: keyof typeof this.DOMAIN_SEPARATORS): Scalar {
        try {
            // Input validasyonu
            if (!(input instanceof Uint8Array)) {
                throw new HashError('Input must be Uint8Array');
            }
            if (input.length === 0) {
                throw new HashError('Input cannot be empty');
            }
            if (input.length > 1024) { // Makul bir üst limit
                throw new HashError('Input too large');
            }

            const domain = this.DOMAIN_SEPARATORS[operation];
            if (domain < 0 || domain > 255) {
                throw new HashError('Invalid domain separator');
            }

            const dataToHash = new Uint8Array([...input, domain]);
            const hash = sha512(dataToHash);
            
            // PSD8 specific masking
            const masked = new Uint8Array(hash.slice(0, 32));
            masked[0] &= 0xFC;  // Clear bottom 2 bits
            masked[31] &= 0x7F; // Clear top bit
            masked[31] |= 0x40; // Set second-to-top bit
            
            // Additional PSD8 validation
            if ((masked[0] & 0x03) !== 0 || (masked[31] & 0xC0) !== 0x40) {
                throw new HashError('Invalid PSD8 output');
            }
            
            return Scalar.fromBytes(masked);
        } catch (error) {
            if (error instanceof HashError) {
                throw error;
            }
            throw new HashError('Failed to hash to scalar using PSD8');
        }
    }

    static hashToGroup(input: Uint8Array): Group {
        let counter = 0;
        
        while (counter < this.MAX_HASH_ATTEMPTS) {
            try {
                const counterBytes = new Uint8Array([counter]);
                const dataToHash = new Uint8Array([...input, ...counterBytes]);
                const hash = sha512(dataToHash);
                
                // Try to create a group point from the first 32 bytes
                const candidate = Group.fromBytes(hash.slice(0, 32));
                if (candidate.isOnCurve()) {
                    return candidate;
                }
            } catch {
                // Continue to next attempt if point creation fails
            }
            counter++;
        }
        
        throw new HashError('Failed to hash to group point after maximum attempts');
    }

    static hashToField(input: Uint8Array): Uint8Array {
        try {
            const hash = sha512(input);
            return hash.slice(0, 32);
        } catch (error) {
            throw new HashError('Failed to hash to field');
        }
    }
} 