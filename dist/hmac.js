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
// \brief HMAC implementation
//        Generates a HMAC value
//
///////////////////////////////////////////////////////////////////////////////
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    }
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var base_1 = require("./base");
var padding_1 = require("./padding");
var sha1_1 = require("./sha1");
var sha256_1 = require("./sha256");
var sha512_1 = require("./sha512");
/**
 * HMAC class
 */
var HMAC = /** @class */ (function () {
    /**
     * ctor
     * @param {Hash} hasher Hashing function
     */
    function HMAC(hasher) {
        this.hasher = hasher;
        this.hashSize = hasher.hashSize;
        this.B = this.hashSize <= 32 ? 64 : 128; // according to RFC4868
        this.iPad = 0x36;
        this.oPad = 0x5c;
    }
    /**
     * Init the HMAC
     * @param {Uint8Array} key The key
     */
    HMAC.prototype.init = function (key) {
        // process the key
        var _key = new Uint8Array(key);
        if (_key.length > this.B) {
            // keys longer than blocksize are shortened
            this.hasher.init();
            _key = this.hasher.digest(key);
        }
        _key = (new padding_1.ZeroPadding()).pad(_key, this.B);
        // setup the key pads
        this.iKeyPad = new Uint8Array(this.B);
        this.oKeyPad = new Uint8Array(this.B);
        for (var i = 0; i < this.B; ++i) {
            this.iKeyPad[i] = this.iPad ^ _key[i];
            this.oKeyPad[i] = this.oPad ^ _key[i];
        }
        // security: delete the key
        base_1.Util.clear(_key);
        // initial hash
        this.hasher.init();
        this.hasher.update(this.iKeyPad);
        return this;
    };
    /**
     * Update the HMAC with additional message data
     * @param {Uint8Array} msg Additional message data
     * @return {HMAC} this object
     */
    HMAC.prototype.update = function (msg) {
        msg = msg || new Uint8Array(0);
        this.hasher.update(msg);
        return this;
    };
    /**
     * Finalize the HMAC with additional message data
     * @param {Uint8Array} msg Additional message data
     * @return {Uint8Array} HMAC (Hash-based Message Authentication Code)
     */
    HMAC.prototype.digest = function (msg) {
        msg = msg || new Uint8Array(0);
        var sum1 = this.hasher.digest(msg); // get sum 1
        this.hasher.init();
        return this.hasher.update(this.oKeyPad).digest(sum1);
    };
    /**
     * All in one step
     * @param {Uint8Array} key Key
     * @param {Uint8Array} msg Message data
     * @return {Uint8Array} Hash as byte array
     */
    HMAC.prototype.hash = function (key, msg) {
        return this.init(key).digest(msg);
    };
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    HMAC.prototype.selftest = function () {
        return false;
    };
    return HMAC;
}());
exports.HMAC = HMAC;
///////////////////////////////////////////////////////////////////////////////
var HMAC_SHA1 = /** @class */ (function (_super) {
    __extends(HMAC_SHA1, _super);
    function HMAC_SHA1() {
        return _super.call(this, new sha1_1.SHA1()) || this;
    }
    return HMAC_SHA1;
}(HMAC));
exports.HMAC_SHA1 = HMAC_SHA1;
var HMAC_SHA256 = /** @class */ (function (_super) {
    __extends(HMAC_SHA256, _super);
    function HMAC_SHA256() {
        return _super.call(this, new sha256_1.SHA256()) || this;
    }
    return HMAC_SHA256;
}(HMAC));
exports.HMAC_SHA256 = HMAC_SHA256;
var HMAC_SHA512 = /** @class */ (function (_super) {
    __extends(HMAC_SHA512, _super);
    function HMAC_SHA512() {
        return _super.call(this, new sha512_1.SHA512()) || this;
    }
    return HMAC_SHA512;
}(HMAC));
exports.HMAC_SHA512 = HMAC_SHA512;
