"use strict";
///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015-2016, PALANDesign Hannover, Germany
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
// \brief PBKDF2 implementation
//        Password-Based Key Derivation Function 2, takes a hash/HMAC function and
//        generates a derived, streched password key due to iteration rounds.
//        At least a minimum of 10000 rounds are recommended!
//
///////////////////////////////////////////////////////////////////////////////
Object.defineProperty(exports, "__esModule", { value: true });
var base_1 = require("./base");
var sha256_1 = require("./sha256");
var hmac_1 = require("./hmac");
/**
 * PBKDF2 class
 */
var PBKDF2 = /** @class */ (function () {
    /**
     * ctor
     * @param {KeyedHash} hmac HMAC function like HMAC-SHA1 or HMAC-SHA256
     * @param {Number} rounds Optional, number of iterations, defaults to 10000
     */
    function PBKDF2(hmac, rounds) {
        if (rounds === void 0) { rounds = 10000; }
        this.hmac = hmac;
        this.rounds = rounds;
    }
    /**
     * Generate derived key
     * @param {Uint8Array} password The password
     * @param {Uint8Array} salt The salt
     * @param {Number} length Optional, the derived key length (dkLen), defaults to the half of the HMAC block size
     * @return {Uint8Array} The derived key as byte array
     */
    PBKDF2.prototype.hash = function (password, salt, length) {
        var u, ui;
        length = length || (this.hmac.hashSize >>> 1);
        var out = new Uint8Array(length);
        for (var k = 1, len = Math.ceil(length / this.hmac.hashSize); k <= len; k++) {
            u = ui = this.hmac.init(password).update(salt).digest(new Uint8Array([(k >>> 24) & 0xFF, (k >>> 16) & 0xFF, (k >>> 8) & 0xFF, k & 0xFF]));
            for (var i = 1; i < this.rounds; i++) {
                ui = this.hmac.hash(password, ui);
                for (var j = 0; j < ui.length; j++) {
                    u[j] ^= ui[j];
                }
            }
            // append data
            out.set(u.subarray(0, k * this.hmac.hashSize < length ? this.hmac.hashSize : length - (k - 1) * this.hmac.hashSize), (k - 1) * this.hmac.hashSize);
        }
        return out;
    };
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    PBKDF2.prototype.selftest = function () {
        var tv = {
            key: 'password',
            salt: 'salt',
            c: 2,
            sha256: 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
        };
        var pbkdf2_sha256 = new PBKDF2(new hmac_1.HMAC(new sha256_1.SHA256()), tv.c);
        var key = base_1.Convert.str2bin(tv.key);
        var salt = base_1.Convert.str2bin(tv.salt);
        var mac = pbkdf2_sha256.hash(key, salt, base_1.Convert.hex2bin(tv.sha256).length);
        return base_1.Convert.bin2hex(mac) === tv.sha256;
    };
    return PBKDF2;
}());
exports.PBKDF2 = PBKDF2;
