import { NetworkParameters } from './types';
import { CryptoError } from './errors';

export class Network {
    private readonly parameters: NetworkParameters;

    constructor(parameters: NetworkParameters) {
        this.validateParameters(parameters);
        this.parameters = parameters;
    }

    validateParameters(params: NetworkParameters): void {
        if (!params.name || typeof params.name !== 'string') {
            throw new CryptoError('Invalid network name');
        }
        if (!params.privateKeyPrefix || typeof params.privateKeyPrefix !== 'string') {
            throw new CryptoError('Invalid private key prefix');
        }
        if (!params.viewKeyPrefix || typeof params.viewKeyPrefix !== 'string') {
            throw new CryptoError('Invalid view key prefix');
        }
        if (!params.computeKeyPrefix || typeof params.computeKeyPrefix !== 'string') {
            throw new CryptoError('Invalid compute key prefix');
        }
        if (!params.signaturePrefix || typeof params.signaturePrefix !== 'string') {
            throw new CryptoError('Invalid signature prefix');
        }
        if (params.addressPrefix.length < 1 || params.addressPrefix.length > 83) {
            throw new CryptoError('Invalid address prefix length');
        }
        const validChars = /^[a-z0-9]+$/;
        if (!validChars.test(params.addressPrefix)) {
            throw new CryptoError('Invalid address prefix characters');
        }
        if (!params.privateKeyPrefix.startsWith('APrivateKey')) {
            throw new CryptoError('Invalid private key prefix format');
        }
        if (!params.viewKeyPrefix.startsWith('AViewKey')) {
            throw new CryptoError('Invalid view key prefix format');
        }
    }

    static mainnet(): Network {
        return new Network({
            name: 'mainnet',
            addressPrefix: 'aleo',
            privateKeyPrefix: 'APrivateKey1',
            viewKeyPrefix: 'AViewKey1',
            computeKeyPrefix: 'AComputeKey1',
            signaturePrefix: 'sign1'
        });
    }

    static testnet(): Network {
        return new Network({
            name: 'testnet',
            addressPrefix: 'aleo',
            privateKeyPrefix: 'APrivateKey1',
            viewKeyPrefix: 'AViewKey1',
            computeKeyPrefix: 'AComputeKey1',
            signaturePrefix: 'sign1'
        });
    }

    getName(): string {
        return this.parameters.name;
    }

    getAddressPrefix(): string {
        return this.parameters.addressPrefix;
    }

    getPrivateKeyPrefix(): string {
        return this.parameters.privateKeyPrefix;
    }

    getViewKeyPrefix(): string {
        return this.parameters.viewKeyPrefix;
    }

    getComputeKeyPrefix(): string {
        return this.parameters.computeKeyPrefix;
    }

    getSignaturePrefix(): string {
        return this.parameters.signaturePrefix;
    }
} 
