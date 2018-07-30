"use strict";
///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015, PALANDesign Hannover, Germany
//
// \license The MIT License (MIT)
//
// This file is part of the mipher crypto library.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// \brief block cipher modes implementation
// usage: var aes = new mipher.blockmode(new mipher.rijndael())
//
///////////////////////////////////////////////////////////////////////////////
Object.defineProperty(exports, "__esModule", { value: true });
var ECB = /** @class */ (function () {
    /**
     * ECB ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    function ECB(blockcipher) {
        this.blockcipher = blockcipher;
    }
    /**
     * ECB mode encryption
     * This mode just passes the input to the output - unsecure, use just for testing!
     * iv is unused
     */
    ECB.prototype.encrypt = function (key, pt, iv) {
        return this.blockcipher.encrypt(key, pt);
    };
    /**
     * ECB mode decryption
     * This mode just passes the input to the output - unsecure, use just for testing!
     * iv is unused
     */
    ECB.prototype.decrypt = function (key, ct, iv) {
        return this.blockcipher.decrypt(key, ct);
    };
    return ECB;
}());
exports.ECB = ECB;
//////////////////////////////////////////////////////////////////////////
var CBC = /** @class */ (function () {
    /**
     * CBC ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    function CBC(blockcipher) {
        this.blockcipher = blockcipher;
    }
    /**
     * CBC mode encryption
     */
    CBC.prototype.encrypt = function (key, pt, iv) {
        var bs = this.blockcipher.blockSize, ct = new Uint8Array(pt.length), et = new Uint8Array(bs);
        // process first block
        for (var f = 0; f < bs; f++) {
            et[f] = pt[f] ^ (iv[f] || 0);
        }
        ct.set(this.blockcipher.encrypt(key, et), 0);
        // process the other blocks
        for (var b = 1, len = pt.length / bs; b < len; b++) {
            for (var i = 0; i < bs; i++) {
                et[i] = pt[i + (b * bs)] ^ ct[i + ((b - 1) * bs)];
            }
            ct.set(this.blockcipher.encrypt(key, et), b * bs);
        }
        return ct;
    };
    /**
     * CBC mode decryption
     */
    CBC.prototype.decrypt = function (key, ct, iv) {
        var bs = this.blockcipher.blockSize, pt = new Uint8Array(ct.length);
        // process first block
        pt.set(this.blockcipher.decrypt(key, ct.subarray(0, bs)), 0);
        for (var i = 0, len = bs; i < len; i++) {
            pt[i] = pt[i] ^ (iv[i] || 0);
        }
        // process other blocks
        for (var b = 1, l = ct.length / bs; b < l; b++) {
            pt.set(this.blockcipher.decrypt(key, ct.subarray(b * bs, (b + 1) * bs)), b * bs);
            for (var i = 0; i < bs; i++) {
                pt[i + (b * bs)] = pt[i + (b * bs)] ^ ct[i + ((b - 1) * bs)];
            }
        }
        return pt;
    };
    return CBC;
}());
exports.CBC = CBC;
//////////////////////////////////////////////////////////////////////////
var CTR = /** @class */ (function () {
    /**
     * CTR ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    function CTR(blockcipher) {
        this.blockcipher = blockcipher;
        // init counter
        this.ctr = new Uint8Array(this.blockcipher.blockSize);
    }
    /**
     * CTR mode encryption
     */
    CTR.prototype.encrypt = function (key, pt, iv) {
        var bs = this.blockcipher.blockSize, ct = new Uint8Array(pt.length);
        this.ctr.set(iv || this.ctr);
        // process blocks
        for (var b = 0, len = pt.length / bs; b < len; b++) {
            ct.set(this.blockcipher.encrypt(key, this.ctr), b * bs);
            for (var i = 0; i < bs; i++) {
                ct[i + (b * bs)] ^= pt[i + (b * bs)];
            }
            // increment the counter
            this.ctr[0]++;
            for (var i = 0; i < bs - 1; i++) {
                if (this.ctr[i] === 0) {
                    this.ctr[i + 1]++;
                }
                else
                    break;
            }
        }
        return ct;
    };
    /**
     * CTR mode decryption
     */
    CTR.prototype.decrypt = function (key, ct, iv) {
        var bs = this.blockcipher.blockSize, pt = new Uint8Array(ct.length);
        this.ctr.set(iv || this.ctr);
        // process blocks
        for (var b = 0, len = ct.length / bs; b < len; b++) {
            pt.set(this.blockcipher.encrypt(key, this.ctr), b * bs);
            for (var i = 0; i < bs; i++) {
                pt[i + (b * bs)] ^= ct[i + (b * bs)];
            }
            // increment the counter
            this.ctr[0]++;
            for (var i = 0; i < bs - 1; i++) {
                if (this.ctr[i] === 0) {
                    this.ctr[i + 1]++;
                }
                else
                    break;
            }
        }
        return pt;
    };
    return CTR;
}());
exports.CTR = CTR;
