import { PrivateKey } from "../account/privateKey";
import { ViewKey } from "../account/viewKey";
import { Address } from "../account/address";

// Raw binary types
export type RawField = Uint8Array & { readonly __type: unique symbol };
export type RawGroup = Uint8Array & { readonly __type: unique symbol };
export type RawScalar = Uint8Array & { readonly __type: unique symbol };

// Base interface for all Aleo objects
export interface AleoObject {
    toBytes(): Uint8Array;
    toString(network: Network): string;
    equals(other: this): boolean;
}

// Interfaces for cryptographic operations
export interface ICryptoScalar extends AleoObject {
    toRawBytes(): RawScalar;
    add(other: ICryptoScalar): ICryptoScalar;
    mul(other: ICryptoScalar): ICryptoScalar;
    negate(): ICryptoScalar;
    equals(other: ICryptoScalar): boolean;
}

export interface ICryptoGroup extends AleoObject {
    toRawBytes(): RawGroup;
    add(other: ICryptoGroup): ICryptoGroup;
    multiply(scalar: ICryptoScalar): ICryptoGroup;
    equals(other: ICryptoGroup): boolean;
    isValid(): boolean;
}

export interface Network {
    name: string;
    addressPrefix: string;
    privateKeyPrefix: string;
    viewKeyPrefix: string;
    computeKeyPrefix: string;
    signaturePrefix: string;
    getAddressPrefix(): string;
    getPrivateKeyPrefix(): string;
    getViewKeyPrefix(): string;
    getComputeKeyPrefix(): string;
    getSignaturePrefix(): string;
}

export interface NetworkParameters {
    name: string;
    addressPrefix: string;
    privateKeyPrefix: string;
    viewKeyPrefix: string;
    computeKeyPrefix: string;
    signaturePrefix: string;
}


export interface KeyPair {
    privateKey: PrivateKey;
    viewKey: ViewKey;
    address: Address;
}

export interface SerializableObject {
    toBytes(): Uint8Array;
    toString(network: Network): string;
}

export interface FromBytes<T> {
    fromBytes(bytes: Uint8Array): T;
}

export interface FromString<T> {
    fromString(str: string): T;
}

export interface AleoObject extends SerializableObject {
    equals(other: this): boolean;
} 