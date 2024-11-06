import { AleoObject, Network } from '../core/types';
import { Group } from '../crypto/group';
import { AccountObject } from './base';

export interface IAddress {
    toBytes(): Uint8Array;
    toString(network: Network): string;
    equals(other: IAddress): boolean;
}

export interface IPrivateKey extends AccountObject {
    toViewKey(network: Network): IViewKey;
    toComputeKey(network: Network): IComputeKey;
    toAddress(network: Network): IAddress;
}

export interface IViewKey extends AccountObject {
    toAddress(network: Network): IAddress;
    toString(network: Network): string;
    decrypt(ciphertext: Uint8Array): Uint8Array;
}

export interface IComputeKey extends AccountObject {
    toAddress(network: Network): IAddress;
    toString(network: Network): string;
    getPkSig(): Group;
}