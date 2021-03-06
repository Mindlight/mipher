"use strict";
///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015-2018, PALANDesign Hannover, Germany
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
// \brief Bruce Schneier's FORTUNA random generator implementation
//        Some inspiration was taken from the random.js module of sjcl
// usage: let rand = new Random();
//        let val = rand.get(32);
//
///////////////////////////////////////////////////////////////////////////////
Object.defineProperty(exports, "__esModule", { value: true });
var base_1 = require("./base");
var aes_1 = require("./aes");
var sha256_1 = require("./sha256");
/**
 * FORTUNA random class
 */
var Random = /** @class */ (function () {
    /**
     * ctor
     * @param {Number} numPools Number of pools used for entropy acquisition. Defaults to 32 pools, use 16 on limited entropy sources
     * @param {Uint8Array} entropy Optional array of any length with initial (true) random data (the more the better)
     */
    function Random(numPools, entropy) {
        if (numPools === void 0) { numPools = 32; }
        // constants
        this.NUM_POOLS = numPools; // number of pools used for entropy acquisition. Defaults to 32 pools, use 16 on limited entropy sources
        this.RESEED_LIMIT = 64; // reseed trigger level
        this.MILLISECONDS_PER_RESEED = 10000; // reseed force after milliseconds
        this.gen = new aes_1.AES();
        this.genKey = new Uint8Array(32);
        this.genCnt = new Uint8Array(16);
        this.poolData = []; // SHA objects
        this.poolEntropy = []; // entropy of the according pool
        this.robin = { kbd: 0, mouse: 0, scroll: 0, touch: 0, motion: 0, time: 0, rnd: 0, dom: 0 };
        this.entropy_level = 0; // actual generator entropy
        this.eventId = 0;
        this.reseedCnt = 0;
        this.lastReseed = 0; // time of last reseed
        this.active = false; // genarator / collectors status
        // create the data pools
        for (var i = 0; i < this.NUM_POOLS; i++) {
            this.poolData.push(new sha256_1.SHA256());
            this.poolEntropy.push(0);
        }
        this.init(entropy);
    }
    /**
     * Start the generator (public wrapper for init())
     * Normally start/stop is not necessary, init() is called from ctor
     */
    Random.prototype.start = function () {
        this.init();
    };
    /**
     * Stop the generator
     * Normally stopping is not necessary
     */
    Random.prototype.stop = function () {
        this.stopCollectors();
    };
    /**
     * Return the actual generator entropy (number of available random bytes)
     * @return {Number} Number of available random bytes
     */
    Random.prototype.getEntropy = function () {
        return Math.floor(this.entropy_level / 8);
    };
    /**
     * Add external given entropy
     * @param {Uint8Array} entropy Random bytes to be added to the entropy pools
     */
    Random.prototype.addEntropy = function (entropy) {
        this.addRandomEvent(entropy, this.robin.rnd, entropy.length * 8);
    };
    ///////////////////////////////////////////////////////////////////////////////
    // G E N E R A T O R
    /**
     * Init/start the module (called by ctor as 'autostart')
     * @param {Uint8Array} entropy Optional array of any length of (true) random bytes to be added to the entropy pools
     */
    Random.prototype.init = function (entropy) {
        // pool init
        var i;
        for (i = 0; i < this.NUM_POOLS; i++) {
            this.poolData[i].init();
        }
        // explicit generator init
        for (i = 0; i < 32; i++) {
            this.genKey[i] = 0;
        } // 32 byte key for AES256
        for (i = 0; i < 16; i++) {
            this.genCnt[i] = 0;
        } // 16 byte counter
        this.robin.kbd = this.robin.mouse = this.robin.scroll = this.robin.touch = this.robin.motion = this.robin.time = this.robin.rnd = this.robin.dom = 0;
        this.reseedCnt = 0;
        this.lastReseed = 0;
        // try to get an initial seed, use crypto.random instead of a seed file
        for (i = 0; i < this.NUM_POOLS * 4; i++) {
            this.collectorCryptoRandom();
        }
        if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
            this.addRandomEvent(base_1.Convert.str2bin(performance.now().toString()), this.robin.time, 2);
        }
        if (typeof process !== 'undefined' && typeof process.hrtime === 'function') {
            this.addRandomEvent(base_1.Convert.str2bin(process.hrtime()[0].toString() + process.hrtime()[1].toString()), this.robin.time, 2);
        }
        // add some entropy from DOM
        this.collectorDom();
        // extra entropy
        if (entropy) {
            this.addRandomEvent(entropy, this.robin.rnd, entropy.length * 8); // add given entropy
        }
        this.startCollectors();
    };
    /**
     * Reseed the generator with the given byte array
     */
    Random.prototype.reseed = function (seed) {
        // compute a new 32 byte key
        this.genKey = (new sha256_1.SHA256()).update(this.genKey).digest(seed);
        // increment the 16 byte counter to make it nonzero and mark the generator as seeded
        this.genCnt[0]++;
        for (var i = 0; i < 15; i++) {
            if (this.genCnt[i] === 0) {
                this.genCnt[i + 1]++;
            }
            else
                break;
        }
        this.lastReseed = (new Date()).valueOf();
    };
    /**
     * Internal function to generates a number of (16 byte) blocks of random output
     * @param {Number} blocks Number of blocks to generate
     */
    Random.prototype.generateBlocks = function (blocks) {
        var r = new Uint8Array(blocks * 16);
        for (var i = 0; i < blocks; i++) {
            r.set(this.gen.encrypt(this.genKey, this.genCnt), i * 16);
            // increment the 16 byte counter
            this.genCnt[0]++;
            for (var c = 0; c < 15; c++) {
                if (this.genCnt[c] === 0) {
                    this.genCnt[c + 1]++;
                }
                else
                    break;
            }
        }
        return r;
    };
    /**
     * Internal function to get random data bytes
     */
    Random.prototype.pseudoRandomData = function (length) {
        var r = new Uint8Array(length);
        // compute the output
        r.set(this.generateBlocks((length >>> 4) + 1).subarray(0, length));
        // generate two more blocks to get a new key
        this.genKey = this.generateBlocks(2);
        return r;
    };
    ///////////////////////////////////////////////////////////////////////////////
    // A C C U M U L A T O R
    /**
     * Get random data bytes
     * @param {Number} length Number of bytes to generate
     * @return {Uint8Array} Byte array of crypto secure random values or undefined, if generator is not ready
     */
    Random.prototype.get = function (length) {
        if ((this.poolEntropy[0] >= this.RESEED_LIMIT) && (this.lastReseed + this.MILLISECONDS_PER_RESEED < (new Date()).valueOf())) {
            // we need to reseed
            this.reseedCnt = ++this.reseedCnt & 0xffffffff;
            var s = new Uint8Array(0), strength = 0;
            for (var i = 0; i < this.NUM_POOLS; i++) {
                if ((1 << i) & this.reseedCnt) {
                    s = base_1.Util.concat(s, this.poolData[i].digest());
                    strength += this.poolEntropy[i];
                    this.poolData[i].init();
                    this.poolEntropy[i] = 0;
                }
            }
            // how strong was this reseed?
            this.entropy_level -= strength;
            // got the data, now do the reseed
            this.reseed(s);
        }
        if (!this.active || this.reseedCnt === 0) {
            return; // error, prng not running or not seeded yet, return undefined
        }
        else {
            return this.pseudoRandomData(length);
        }
    };
    ///////////////////////////////////////////////////////////////////////////////
    // C O L L E C T O R S
    /**
     * Start the built-in entropy collectors
     */
    Random.prototype.startCollectors = function () {
        if (this.active) {
            return;
        }
        if (typeof window !== 'undefined' && window.addEventListener) {
            window.addEventListener('click', this.collectorClick.bind(this), true);
            window.addEventListener('keydown', this.collectorKeyboard.bind(this), true);
            window.addEventListener('scroll', this.collectorScroll.bind(this), true);
            window.addEventListener('mousemove', this.throttle(this.collectorMouse, 50, this), true);
            window.addEventListener('devicemotion', this.throttle(this.collectorMotion, 100, this), true);
            window.addEventListener('deviceorientation', this.collectorMotion.bind(this), true);
            window.addEventListener('orientationchange', this.collectorMotion.bind(this), true);
            window.addEventListener('touchmove', this.throttle(this.collectorTouch, 50, this), true);
            window.addEventListener('touchstart', this.collectorTouch.bind(this), true);
            window.addEventListener('touchend', this.collectorTouch.bind(this), true);
            window.addEventListener('load', this.collectorTime.bind(this), true);
        }
        else if (typeof document !== 'undefined' && document.addEventListener) {
            document.addEventListener('click', this.collectorClick.bind(this), true);
            document.addEventListener('keydown', this.collectorKeyboard.bind(this), true);
            document.addEventListener('mousemove', this.throttle(this.collectorMouse, 50, this), true);
        }
        // start timer, add additional crypto random from system source every 3 sec
        this.timer = setInterval(this.collectorCryptoRandom.bind(this), 3000);
        this.active = true;
    };
    /**
     * Stop the built-in entropy collectors
     */
    Random.prototype.stopCollectors = function () {
        if (!this.active) {
            return;
        }
        if (typeof window !== 'undefined' && window.addEventListener) {
            window.removeEventListener('click', this.collectorClick, true);
            window.removeEventListener('keydown', this.collectorKeyboard, true);
            window.removeEventListener('scroll', this.collectorScroll, true);
            window.removeEventListener('mousemove', this.collectorMouse, true);
            window.removeEventListener('devicemotion', this.collectorMotion, true);
            window.removeEventListener('deviceorientation', this.collectorMotion, true);
            window.removeEventListener('orientationchange', this.collectorMotion, true);
            window.removeEventListener('touchmove', this.collectorTouch, true);
            window.removeEventListener('touchstart', this.collectorTouch, true);
            window.removeEventListener('touchend', this.collectorTouch, true);
            window.removeEventListener('load', this.collectorTime, true);
        }
        else if (typeof document !== 'undefined' && document.addEventListener) {
            document.removeEventListener('click', this.collectorClick, true);
            document.removeEventListener('keydown', this.collectorKeyboard, true);
            document.removeEventListener('mousemove', this.collectorMouse, true);
        }
        // stop timer
        clearInterval(this.timer);
        this.active = false;
    };
    /**
     * In case of an event burst (eg. motion events), this executes the given fn once every threshold
     * @param {Function} fn Function to be throttled
     * @param {number} threshold Threshold in [ms]
     * @param {Object} scope Optional scope, defaults to 'this'
     * @returns {Function} Resulting function
     */
    Random.prototype.throttle = function (fn, threshold, scope) {
        var last, deferTimer;
        return function () {
            var context = scope || this;
            var now = +new Date, args = arguments;
            if (last && now < last + threshold) {
                clearTimeout(deferTimer);
                deferTimer = setTimeout(function () {
                    last = now;
                    fn.apply(context, args);
                }, threshold);
            }
            else {
                last = now;
                fn.apply(context, args);
            }
        };
    };
    /**
     * Add entropy data to pool
     * @param data {Uint8Array} Entropy data to add
     * @param pool_idx {Number} Pool index number to add the entropy data to
     * @param entropy {Number} Added entropy data quality in bits
     */
    Random.prototype.addRandomEvent = function (data, pool_idx, entropy) {
        if (entropy === void 0) { entropy = 1; }
        this.poolEntropy[pool_idx] += entropy;
        this.entropy_level += entropy;
        this.poolData[pool_idx].update(base_1.Convert.int2bin(this.eventId++)).update(data);
    };
    Random.prototype.collectorKeyboard = function (ev) {
        this.addRandomEvent(new Uint8Array([base_1.Convert.str2bin(ev.key || ev.char)[0] || ev.keyCode, (ev.timeStamp || 0) & 0xFF]), this.robin.kbd, 1);
        this.robin.kbd = ++this.robin.kbd % this.NUM_POOLS;
        this.collectorTime();
    };
    Random.prototype.collectorMouse = function (ev) {
        var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
        this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.mouse, 2);
        this.robin.mouse = ++this.robin.mouse % this.NUM_POOLS;
    };
    Random.prototype.collectorClick = function (ev) {
        var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
        this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.mouse, 2);
        this.robin.mouse = ++this.robin.mouse % this.NUM_POOLS;
        this.collectorTime();
    };
    Random.prototype.collectorTouch = function (ev) {
        var touch = ev.touches[0] || ev.changedTouches[0];
        var x = touch.pageX || touch.clientX || 0, y = touch.pageY || touch.clientY || 0;
        this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.touch, 2);
        this.robin.touch = ++this.robin.touch % this.NUM_POOLS;
        this.collectorTime();
    };
    Random.prototype.collectorScroll = function (ev) {
        var x = window.pageXOffset || window.scrollX, y = window.pageYOffset || window.scrollY;
        this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.scroll, 1);
        this.robin.scroll = ++this.robin.scroll % this.NUM_POOLS;
    };
    Random.prototype.collectorMotion = function (ev) {
        if (typeof ev !== 'undefined' && typeof ev.accelerationIncludingGravity !== 'undefined') {
            var x = ev.accelerationIncludingGravity.x || 0, y = ev.accelerationIncludingGravity.y || 0, z = ev.accelerationIncludingGravity.z || 0;
            this.addRandomEvent(new Uint8Array([(x * 100) & 0xff, (y * 100) & 0xff, (z * 100) & 0xff]), this.robin.motion, 3);
        }
        if (typeof ev !== 'undefined' && typeof ev.alpha === 'number' && typeof ev.beta === 'number' && typeof ev.gamma === 'number') {
            this.addRandomEvent(base_1.Convert.str2bin(ev.alpha.toString() + ev.beta.toString() + ev.gamma.toString()), this.robin.motion, 3);
        }
        if (typeof window !== 'undefined' && typeof window.orientation !== 'undefined') {
            this.addRandomEvent(base_1.Convert.str2bin(window.orientation.toString()), this.robin.motion, 1);
        }
        this.robin.motion = ++this.robin.motion % this.NUM_POOLS;
    };
    Random.prototype.collectorTime = function () {
        if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
            this.addRandomEvent(base_1.Convert.str2bin(performance.now().toString()), this.robin.time, 2);
        }
        else {
            this.addRandomEvent(base_1.Convert.number2bin(Date.now()), this.robin.time, 2);
        }
        this.robin.time = ++this.robin.time % this.NUM_POOLS;
    };
    Random.prototype.collectorDom = function () {
        if (typeof document !== 'undefined' && document.documentElement) {
            this.addRandomEvent((new sha256_1.SHA256()).hash(base_1.Convert.str2bin(document.documentElement.innerHTML)), this.robin.dom, 2);
            this.robin.dom = ++this.robin.dom % this.NUM_POOLS;
        }
    };
    Random.prototype.collectorCryptoRandom = function () {
        // check if running in nodeish env
        if (typeof process !== 'undefined' && typeof process.pid === 'number') {
            // running on node
            try {
                var crypto_1 = require('react-native-crypto');
                var rnd = crypto_1.randomBytes(128);
                this.addRandomEvent(rnd, this.robin.rnd, 1024);
                this.robin.rnd = ++this.robin.rnd % this.NUM_POOLS;
            }
            catch (e) { }
        }
        if (typeof window !== 'undefined' && window.crypto && typeof window.crypto.getRandomValues === 'function') {
            // running in browser env
            try {
                var rnd = new Uint8Array(128);
                window.crypto.getRandomValues(rnd);
                this.addRandomEvent(rnd, this.robin.rnd, 1024);
                this.robin.rnd = ++this.robin.rnd % this.NUM_POOLS;
            }
            catch (e) { }
        }
    };
    return Random;
}());
exports.Random = Random;
