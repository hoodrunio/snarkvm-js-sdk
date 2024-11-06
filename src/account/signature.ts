import { Scalar } from '../crypto/scalar';
import { Group } from '../crypto/group';
import { HashUtils } from '../crypto/hash';
import { ComputeKey } from './computeKey';
import { PrivateKey } from './privateKey';
import { Address } from './address';
import { Network } from '../core/types';
import { AccountObject } from './base';
import { CryptoError, SignatureError } from '../core/errors';
import { Encoding } from '../crypto/encoding';

export class Signature implements AccountObject {
    private readonly challenge: Scalar;
    private readonly response: Scalar;
    private readonly computeKey: ComputeKey;

    constructor(challenge: Scalar, response: Scalar, computeKey: ComputeKey) {
        if (!(challenge instanceof Scalar)) {
            throw new SignatureError('Challenge must be a Scalar instance');
        }
        if (!(response instanceof Scalar)) {
            throw new SignatureError('Response must be a Scalar instance');
        }
        if (!(computeKey instanceof ComputeKey)) {
            throw new SignatureError('ComputeKey must be a ComputeKey instance');
        }
        this.challenge = challenge;
        this.response = response;
        this.computeKey = computeKey;
    }

/**
     * Signs a message using the provided private key
     * @param message - The message to sign as a Uint8Array
     * @param privateKey - The private key to sign with
     * @param network - The network parameters
     * @returns A signature object
     * @throws {SignatureError} If signing fails
     */

    static sign(message: Uint8Array, privateKey: PrivateKey, network: Network): Signature {
        try {
            const computeKey = privateKey.toComputeKey(network);
            const randomScalar = Scalar.random();
            const g_r = Group.BASE_POINT.multiply(randomScalar);
            
            // Create hash input: (g_r, pk_sig, pr_sig, address, message)
            const preimage = Buffer.concat([
                g_r.toX(),
                computeKey.getPkSig().toX(),
                computeKey.getPrSig().toX(),
                privateKey.toAddress(network).toBytes(),
                message
            ]);
            
            // Use PSD8 hash
            const challenge = HashUtils.hashToScalarPsd8(preimage);
            const response = randomScalar.add(challenge.multiply(privateKey.toScalar()));
            
            return new Signature(challenge, response, computeKey);
        } catch (error) {
            throw new SignatureError('Failed to create signature');
        }
    }

    verify(message: Uint8Array, address: Address, network: Network): boolean {
        try {
            // 1. Compute key validation
            const pkSig = this.computeKey.getPkSig();
            const prSig = this.computeKey.getPrSig();
            if (!(pkSig instanceof Group) || !(prSig instanceof Group)) {
                return false;
            }

            // 2. Calculate g_r: (response * G) + (challenge * pk_sig)
            const gResponse = Group.BASE_POINT.multiply(this.response);
            const pkSigChallenge = pkSig.multiply(this.challenge);
            const g_r = gResponse.add(pkSigChallenge);

            // 3. Create hash input: (g_r, pk_sig, pr_sig, address, message)
            const preimage = Buffer.concat([
                g_r.toX(), // Only x coordinate
                pkSig.toX(),
                prSig.toX(),
                address.toBytes(),
                message
            ]);

            // 4. Use PSD8 hash
            const candidateChallenge = HashUtils.hashToScalarPsd8(preimage);
            if (!this.challenge.equals(candidateChallenge)) {
                return false;
            }

            // 5. Address verification
            const candidateAddress = this.computeKey.toAddress(network);
            return address.equals(candidateAddress);
        } catch (error) {
            return false;
        }
    }

    toAddress(network: Network): Address {
        return this.computeKey.toAddress(network);
    }

    toBytes(): Uint8Array {
        return Buffer.concat([
            this.challenge.toBytes(),
            this.response.toBytes(),
            this.computeKey.toBytes()
        ]);
    }

    toString(network: Network): string {
        const bytes = this.toBytes();
        return Encoding.encodeSignature(bytes, network);
    }

    static fromBytes(bytes: Uint8Array): Signature {
        try {
            const challenge = Scalar.fromBytes(bytes.slice(0, 32));
            const response = Scalar.fromBytes(bytes.slice(32, 64));
            const computeKey = ComputeKey.fromBytes(bytes.slice(64));
            
            return new Signature(challenge, response, computeKey);
        } catch (error) {
            throw new SignatureError('Invalid signature encoding');
        }
    }

    static fromString(signature: string, network: Network): Signature {
        const bytes = Encoding.decodeSignature(signature, network);
        return Signature.fromBytes(bytes);
    }

    equals(other: Signature): boolean {
        return this.challenge.equals(other.challenge) &&
               this.response.equals(other.response) &&
               this.computeKey.equals(other.computeKey);
    }
} 