// from https://github.com/antelle/argon2-browser, modified, MIT
// https://raw.githubusercontent.com/antelle/argon2-browser/master/LICENSE

'use strict';

var calcHashArg;

self.onmessage = function (e) {
    self.postMessage('calc:' + e.data.calc);
    calcHashArg = e.data.arg;
    calcSimd();
};

function loadScript(script, callback, errorCallback) {
    try {
        importScripts(script);
    } catch (e) {
        console.error('Error loading script', script, e);
        errorCallback(e);
        return;
    }
    callback();
}

function post(msg) {
    self.postMessage(msg);
}

function getArg() {
    return calcHashArg;
}

if (navigator.userAgent.indexOf('Edge') >= 0) {
    importScripts('text-encoder-lite.min.js');
}

importScripts('calc.js');
self.postMessage({ msg: 'Worker started' });