import { Address } from './account/address';
import { Network } from './core/types';
import { AleoError } from './core/errors';
import { PrivateKey } from './account/privateKey';
import { KeyDerivationError } from './core/errors';
import { KeyPair } from './core/types';

export { Address } from './account/address';
export { PrivateKey } from './account/privateKey';
export { ViewKey } from './account/viewKey';
export { ComputeKey } from './account/computeKey';
export { Signature } from './account/signature';
export { Network } from './core/types';
export { AleoError } from './core/errors';

export class AleoSDK {
    private network: Network;

    constructor(network: Network) {
        if (!network) {
            throw new AleoError('Network configuration is required', 'AleoSDK');
        }
        this.network = network;
    }

    generateAccount(): KeyPair {
        try {
            const privateKey = PrivateKey.generate();
            const viewKey = privateKey.toViewKey(this.network);
            const address = privateKey.toAddress(this.network);

            return { privateKey, viewKey, address };
        } catch (error) {
            if (error instanceof KeyDerivationError) {
                throw error;
            }
            throw new AleoError('Failed to generate account', 'AleoSDK');
        }
    }

    createAddressFromPrivateKey(privateKeyString: string): Address {
        try {
            const privateKey = PrivateKey.fromString(privateKeyString, this.network);
            return privateKey.toAddress(this.network);
        } catch (error) {
            if (error instanceof KeyDerivationError) {
                throw error;
            }
            throw new AleoError('Failed to create address from private key', 'AleoSDK');
        }
    }
} 