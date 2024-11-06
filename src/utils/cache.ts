import { CacheError } from '../core/errors';

export class Cache<K, V> {
    private readonly cache: Map<K, V>;
    private readonly maxSize: number;

    constructor(maxSize: number = 1000) {
        if (maxSize <= 0) {
            throw new CacheError('Cache size must be positive');
        }
        this.cache = new Map<K, V>();
        this.maxSize = maxSize;
    }

    get(key: K): V | undefined {
        return this.cache.get(key);
    }

    set(key: K, value: V): void {
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            if (firstKey) {
                this.cache.delete(firstKey);
            }
        }
        this.cache.set(key, value);
    }

    has(key: K): boolean {
        return this.cache.has(key);
    }

    clear(): void {
        this.cache.clear();
    }

    size(): number {
        return this.cache.size;
    }
} 