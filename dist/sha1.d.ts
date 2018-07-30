import { Hash } from './base';
/**
 * SHA1 class
 */
export declare class SHA1 implements Hash {
    hashSize: number;
    buffer: Uint8Array;
    bufferIndex: number;
    count: Uint32Array;
    K: Uint32Array;
    H: Uint32Array;
    S: Function;
    F: Function;
    /**
     * SHA1 ctor
     */
    constructor();
    /**
     * Init the hash
     * @return {SHA1} this
     */
    init(): SHA1;
    /**
     * Perform one transformation cycle
     */
    private transform;
    /**
     * Update the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {SHA1} this
     */
    update(msg?: Uint8Array): SHA1;
    /**
     * Finalize the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {Uint8Array} Hash as 20 byte array
     */
    digest(msg?: Uint8Array): Uint8Array;
    /**
     * All in one step
     * @param {Uint8Array} msg Additional message data
     * @return {Uint8Array} Hash as 20 byte array
     */
    hash(msg?: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
