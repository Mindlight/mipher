import { Blockcipher } from './base';
export declare class ECB {
    blockcipher: Blockcipher;
    /**
     * ECB ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    constructor(blockcipher: Blockcipher);
    /**
     * ECB mode encryption
     * This mode just passes the input to the output - unsecure, use just for testing!
     * iv is unused
     */
    encrypt(key: any, pt: any, iv: any): Uint8Array;
    /**
     * ECB mode decryption
     * This mode just passes the input to the output - unsecure, use just for testing!
     * iv is unused
     */
    decrypt(key: any, ct: any, iv: any): Uint8Array;
}
export declare class CBC {
    blockcipher: Blockcipher;
    /**
     * CBC ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    constructor(blockcipher: Blockcipher);
    /**
     * CBC mode encryption
     */
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    /**
     * CBC mode decryption
     */
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
export declare class CTR {
    blockcipher: Blockcipher;
    ctr: Uint8Array;
    /**
     * CTR ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    constructor(blockcipher: Blockcipher);
    /**
     * CTR mode encryption
     */
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    /**
     * CTR mode decryption
     */
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
