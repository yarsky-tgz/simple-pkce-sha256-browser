"use strict";
exports.__esModule = true;
exports.createPKCEHelper = void 0;
var fast_sha256_1 = require("fast-sha256");
var abstract_pkce_1 = require("abstract-pkce");
var windowsCrypto = window.msCrypto;
var standardCrypto = window.crypto;
var dummyCrypto = {
    getRandomValues: function (array) { var _a; return (_a = array) === null || _a === void 0 ? void 0 : _a.map(function () { return Math.floor(Math.random() * 255); }); }
};
var crypto = standardCrypto
    || windowsCrypto
    || dummyCrypto;
var bufferToBase64 = function (input) { return window
    .btoa(String.fromCharCode.apply(String, Array.from(new Uint8Array(input)))); };
exports.createPKCEHelper = function (isHMAC) {
    if (isHMAC === void 0) { isHMAC = true; }
    return abstract_pkce_1.createPKCEHelper({
        getChallenge: isHMAC
            ? function (verifier) { return bufferToBase64(new fast_sha256_1.HMAC(new TextEncoder().encode(verifier)).digest()); }
            : function (verifier) { return bufferToBase64(new fast_sha256_1.Hash().update(new TextEncoder().encode(verifier)).digest()); },
        buildVerifier: function (length, possibleCharsCount, getPossibleChar) { return crypto
            .getRandomValues(new Uint8Array(length))
            .reduce(function (previous, randomValue) { return "" + previous + getPossibleChar(randomValue % possibleCharsCount); }, ''); }
    });
};
