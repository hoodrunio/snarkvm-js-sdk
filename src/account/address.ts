import { Group } from '../crypto/group';
import { Network } from '../core/types';
import { AddressError, KeyDerivationError } from '../core/errors';
import { encodeAddress, decodeAddress } from '../crypto/encoding';
import { AccountObject } from './base';
import { PrivateKey } from './privateKey';
import { HashUtils } from '../crypto/hash';

export class Address implements AccountObject {
    private readonly group: Group;
    
    constructor(group: Group) {
        if (!group) {
            throw new AddressError('Invalid address group');
        }
        this.group = group;
    }

    static fromPrivateKey(privateKey: PrivateKey, network: Network): Address {
        try {
            const viewKey = privateKey.toViewKey(network);
            const addressScalar = HashUtils.hashToScalarPsd8(
                Buffer.concat([
                    Buffer.from(network.getAddressPrefix()),
                    viewKey.toBytes()
                ])
            );
            const addressGroup = Group.BASE_POINT.multiply(addressScalar);
            return new Address(addressGroup);
        } catch (error) {
            if (error instanceof KeyDerivationError) {
                throw error;
            }
            throw new AddressError('Failed to derive address from private key');
        }
    }

    static fromString(address: string, network: Network): Address {
        try {
            // Network prefix check
            if (!address.startsWith(network.getAddressPrefix())) {
                throw new AddressError(`Invalid address prefix for network ${network.name}`);
            }

            const decoded = decodeAddress(address, network);
            return new Address(Group.fromBytes(decoded));
        } catch (error) {
            throw new AddressError('Invalid address format');
        }
    }

    toBytes(): Uint8Array {
        return this.group.toBytes();
    }

    toString(network: Network): string {
        return encodeAddress(this.toBytes(), network);
    }

    equals(other: Address): boolean {
        return this.group.equals(other.group);
    }
} 