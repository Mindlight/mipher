import { Blockcipher, Streamcipher } from './base';
import { CBC, CTR } from './blockmode';
import { PKCS7 } from './padding';
/**
 * Serpent class
 */
export declare class Serpent implements Blockcipher {
    blockSize: number;
    key: Uint32Array;
    wMax: number;
    rotW: Function;
    getW: Function;
    setW: Function;
    setWInv: Function;
    keyIt: Function;
    keyLoad: Function;
    keyStore: Function;
    S: Array<Function>;
    SI: Array<Function>;
    /**
     * Serpent ctor
     */
    constructor();
    /**
     * Init the cipher, private function
     * @param {Uint8Array} key The key. The key size can be 128, 192 or 256 bits
     */
    private init;
    private K;
    private LK;
    private KL;
    /**
     * Serpent block encryption
     * @param {Uint8Array} key Key
     * @param {Uint8Array} pt The plaintext
     * @return {Uint8Array} Ciphertext
     */
    encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array;
    /**
     * Serpent block decryption
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
export declare class Serpent_CBC implements Streamcipher {
    cipher: Serpent;
    blockmode: CBC;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CTR implements Streamcipher {
    cipher: Serpent;
    blockmode: CTR;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CBC_PKCS7 implements Streamcipher {
    cipher: Serpent_CBC;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CTR_PKCS7 implements Streamcipher {
    cipher: Serpent_CTR;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
