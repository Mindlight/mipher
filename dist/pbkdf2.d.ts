import { KeyedHash } from './base';
/**
 * PBKDF2 class
 */
export declare class PBKDF2 {
    private hmac;
    private rounds;
    /**
     * ctor
     * @param {KeyedHash} hmac HMAC function like HMAC-SHA1 or HMAC-SHA256
     * @param {Number} rounds Optional, number of iterations, defaults to 10000
     */
    constructor(hmac: KeyedHash, rounds?: number);
    /**
     * Generate derived key
     * @param {Uint8Array} password The password
     * @param {Uint8Array} salt The salt
     * @param {Number} length Optional, the derived key length (dkLen), defaults to the half of the HMAC block size
     * @return {Uint8Array} The derived key as byte array
     */
    hash(password: Uint8Array, salt: Uint8Array, length?: number): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
