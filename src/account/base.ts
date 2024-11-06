import { AleoObject, Network } from '../core/types';

export interface AccountObject extends AleoObject {
    readonly toBytes: () => Uint8Array;
    readonly toString: (network: Network) => string;
    readonly equals: (other: this) => boolean;
}

// Tip tanımlamaları
export type PrivateKeyBytes = Uint8Array;
export type ViewKeyBytes = Uint8Array;
export type AddressBytes = Uint8Array;