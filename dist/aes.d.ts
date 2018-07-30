import { Blockcipher } from './base';
import { CBC, CTR } from './blockmode';
import { PKCS7 } from './padding';
/**
 * AES class
 */
export declare class AES implements Blockcipher {
    blockSize: number;
    keylen: Object;
    Rcon: Uint8Array;
    S: Uint8Array;
    S5: Uint8Array;
    T1: Uint32Array;
    T2: Uint32Array;
    T3: Uint32Array;
    T4: Uint32Array;
    T5: Uint32Array;
    T6: Uint32Array;
    T7: Uint32Array;
    T8: Uint32Array;
    U1: Uint32Array;
    U2: Uint32Array;
    U3: Uint32Array;
    U4: Uint32Array;
    /**
     * AES ctor
     */
    constructor();
    private B0;
    private B1;
    private B2;
    private B3;
    private F1;
    private packBytes;
    private unpackBytes;
    /**
     * \param {String} key given as array of bytes
     * \return {Object} .rounds and .keySched
     */
    private keyExpansion;
    /**
     * @param {Array} key
     * @return {Object} rk and rounds
     */
    private prepare_decryption;
    /**
     * AES block encryption
     * @param {Uint8Array} key Key
     * @param {Uint8Array} pt The plaintext
     * @return {Uint8Array} Ciphertext
     */
    encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array;
    /**
     * AES block decryption
     * @param {Uint8Array} key Key
     * @param {Uint8Array} ct The ciphertext
     * @return {Uint8Array} Plaintext
     */
    decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
export declare class AES_CBC {
    cipher: AES;
    blockmode: CBC;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
export declare class AES_CTR {
    cipher: AES;
    blockmode: CTR;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
export declare class AES_CBC_PKCS7 {
    cipher: AES_CBC;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
export declare class AES_CTR_PKCS7 {
    cipher: AES_CTR;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
