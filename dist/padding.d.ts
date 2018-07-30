export declare class PKCS7 {
    /**
     * PKCS#7 padding function. Pads bytes to given text until text is multiple of blocksize is met
     * @param {Uint8Array} bin Byte array where the bytes are padded
     * @param {Number} blocksize The blocksize in bytes of the text to which the text should be padded
     * @return {Uint8Array} Padded byte array
     */
    pad(bin: Uint8Array, blocksize: number): Uint8Array;
    /**
     * PKCS#7 stripping function. Strips bytes of the given text
     * @param {Uint8Array} bin Byte array where the bytes are stripped
     * @return {Uint8Array} Stripped byte array
     */
    strip(bin: Uint8Array): Uint8Array;
}
export declare class PKCS5 {
    pkcs7: PKCS7;
    /**
     * PKCS#5 ctor
     */
    constructor();
    /**
     * PKCS#5 padding function. Pads bytes to given text until text is multiple of 8
     * @param {Uint8Array} bin Byte array where the bytes are padded
     * @return {Uint8Array} Padded byte array
     */
    pad(bin: Uint8Array): Uint8Array;
    /**
     * PKCS#5 stripping function. Strips bytes of the given text
     * @param {Uint8Array} bin Byte array where the bytes are stripped
     * @return {Uint8Array} Stripped byte array
     */
    strip(bin: Uint8Array): Uint8Array;
}
export declare class ZeroPadding {
    /**
     * Pads zero bytes to the given array until the length is a multiple of blocksize
     * @param {Uint8Array} bin The text where the zero bytes are padded
     * @param {Number} blocksize The blocksize to which the array should be padded
     * @return {Uint8Array} Padded byte array
     */
    pad(bin: Uint8Array, blocksize: number): Uint8Array;
    /**
     * Zero stripping function. Just a dummy
     * @param {Array} bin Byte array where the bytes are stripped
     */
    strip(bin: Uint8Array): Uint8Array;
}
