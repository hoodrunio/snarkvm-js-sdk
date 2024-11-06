import { Scalar } from '../crypto/scalar';
import { Group } from '../crypto/group';
import { HashUtils } from '../crypto/hash';
import { Network } from '../core/types';
import { Address } from './address';
import { AccountObject } from './base';
import { KeyDerivationError } from '../core/errors';
import { encodeComputeKey, decodeComputeKey } from '../crypto/encoding';

export class ComputeKey implements AccountObject {
    private readonly pkSig: Group;
    private readonly prSig: Group;
    private readonly skPrf: Scalar;

    constructor(pkSig: Group, prSig: Group, skPrf: Scalar) {
        if (!pkSig || !prSig || !skPrf) {
            throw new KeyDerivationError('Invalid compute key components');
        }
        this.pkSig = pkSig;
        this.prSig = prSig;
        this.skPrf = skPrf;
    }

    static fromComponents(skSig: Scalar, prfSeed: Scalar, domain: number = 0x08): ComputeKey {
        const pkSig = Group.BASE_POINT.multiply(skSig);
        const prSig = Group.BASE_POINT.multiply(
            HashUtils.hashToScalarPsd8(Buffer.concat([prfSeed.toBytes(), Buffer.from([HashUtils.DOMAIN_SEPARATORS.COMPUTE_KEY])]), 'COMPUTE_KEY')
        );
        return new ComputeKey(pkSig, prSig, prfSeed);
    }

    static fromBytes(bytes: Uint8Array): ComputeKey {
        try {
            const pkSig = Group.fromBytes(bytes.slice(0, 32));
            const prSig = Group.fromBytes(bytes.slice(32, 64));
            const skPrf = Scalar.fromBytes(bytes.slice(64, 96));
            return new ComputeKey(pkSig, prSig, skPrf);
        } catch (error) {
            throw new KeyDerivationError('Invalid compute key bytes');
        }
    }

    static fromString(computeKeyString: string, network: Network): ComputeKey {
        try {
            const decoded = decodeComputeKey(computeKeyString, network);
            return ComputeKey.fromBytes(decoded);
        } catch (error) {
            throw new KeyDerivationError('Invalid compute key string');
        }
    }

    getPkSig(): Group {
        if (!(this.pkSig instanceof Group)) {
            throw new KeyDerivationError('Invalid compute key signature');
        }
        return this.pkSig;
    }

    toAddress(network: Network): Address {
        try {
            const pkPrf = Group.BASE_POINT.multiply(this.skPrf);
            const step1 = this.pkSig.add(pkPrf);
            const step2 = step1.add(this.prSig);
            
            const addressInput = Buffer.concat([
                step2.toBytes(),
                Buffer.from([HashUtils.DOMAIN_SEPARATORS.ADDRESS])
            ]);
            
            const addressGroup = Group.fromBytes(
                HashUtils.hashToField(addressInput)
            );
            
            return new Address(addressGroup);
        } catch (error) {
            throw new KeyDerivationError('Failed to derive address');
        }
    }

    toBytes(): Uint8Array {
        return Buffer.concat([
            this.pkSig.toBytes(),
            this.prSig.toBytes(),
            this.skPrf.toBytes()
        ]);
    }

    toString(network: Network): string {
        return encodeComputeKey(this.toBytes(), network);
    }

    equals(other: ComputeKey): boolean {
        return this.pkSig.equals(other.pkSig) && 
               this.prSig.equals(other.prSig) && 
               this.skPrf.equals(other.skPrf);
    }
} 