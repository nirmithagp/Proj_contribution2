const LRU = require('lru-cache');

class CacheService {
    constructor() {
        this.cache = new LRU({
            max: 100, // Maximum number of items
            maxAge: 1000 * 60 * 60, // 1 hour TTL (v6 uses maxAge)
            updateAgeOnGet: false,
        });
    }

    /**
     * Get a value from the cache
     * @param {string} key 
     * @returns {any} The cached value or undefined
     */
    get(key) {
        return this.cache.get(key);
    }

    /**
     * Set a value in the cache
     * @param {string} key 
     * @param {any} value 
     * @param {object} options - Optional { maxAge: number }
     */
    set(key, value, options = {}) {
        this.cache.set(key, value, options.ttl ? options.ttl : options.maxAge);
    }

    /**
     * Clear the cache
     */
    flush() {
        this.cache.reset(); // v6 uses reset() instead of clear()? or is it reset? 
        // v6 has reset(). clear() might differ.
    }

    /**
     * Helper to wrap an async function with caching
     * @param {string} key 
     * @param {Function} fetchFn 
     * @param {object} options 
     */
    async getOrSet(key, fetchFn, options = {}) {
        const cached = this.get(key);
        if (cached) {
            console.log(`🚀 Cache hit for key: ${key}`);
            return cached;
        }

        console.log(`🌐 Cache miss for key: ${key}, fetching...`);
        const value = await fetchFn();
        this.set(key, value, options);
        return value;
    }
}

module.exports = new CacheService();
