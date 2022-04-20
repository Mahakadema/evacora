// from https://github.com/antelle/argon2-browser, modified, MIT
// https://raw.githubusercontent.com/antelle/argon2-browser/master/LICENSE

'use strict';

var global = typeof window === 'undefined' ? self : window;
var root = typeof window === 'undefined' ? '../' : '';

function calc(fn) {
    return function (e) {
        e.preventDefault();
        try {
            fn();
        } catch (e) {
            log('Error: ' + e);
        }
    };
}

function calcSimd() {
    calcBinaryen('native-wasm', { simd: true });
}

function calcBinaryen(method, options) {
    if (!global.WebAssembly) {
        post({ encodedHash: null, err: "Your browser doesn't support WebAssembly, please try it in Chrome Canary or Firefox Nightly with WASM flag enabled" });
        return;
    }

    const mem = getArg().mem;

    if (
        global.Module &&
        global.Module.wasmJSMethod === method &&
        global.Module._argon2_hash_ext
    ) {
        setTimeout(calcHash, 10);
        return;
    }

    const KB = 1024 * 1024;
    const MB = 1024 * KB;
    const GB = 1024 * MB;
    const WASM_PAGE_SIZE = 64 * 1024;

    const totalMemory = (2 * GB - 64 * KB) / 1024 / WASM_PAGE_SIZE;
    const initialMemory = Math.min(
        Math.max(Math.ceil((mem * 1024) / WASM_PAGE_SIZE), 256) + 256,
        totalMemory
    );
    const wasmMemory = new WebAssembly.Memory({
        initial: initialMemory,
        maximum: totalMemory,
    });

    global.Module = {
        print: () => null,
        printErr: () => null,
        setStatus: () => null,
        wasmBinary: null,
        wasmJSMethod: method,
        wasmMemory: wasmMemory,
        buffer: wasmMemory.buffer,
        TOTAL_MEMORY: initialMemory * WASM_PAGE_SIZE,
    };

    var wasmFileName = 'argon2.wasm';
    if (options && options.simd) {
        wasmFileName = 'argon2-simd.wasm';
    }

    console.log('Loading wasm...');
    var xhr = new XMLHttpRequest();
    xhr.open('GET', root + 'dist/' + wasmFileName, true);
    xhr.responseType = 'arraybuffer';
    xhr.onload = function () {
        global.Module.wasmBinary = xhr.response;
        global.Module.postRun = calcHash;
        var ts = now();
        console.log('Wasm loaded, loading script...');
        loadScript(
            root + 'dist/argon2.js',
            function () {
                console.log('Script loaded in ' + Math.round(now() - ts) + 'ms');
                console.log('Calculating hash...');
            },
            function () {
                console.log('Error loading script');
            }
        );
    };
    xhr.onerror = function () {
        console.log('Error loading wasm');
    };
    xhr.send(null);
}

function calcHash() {
    var arg = getArg();
    if (!Module._argon2_hash_ext) {
        return console.log('Error');
    }
    console.log(
        'Params: ' +
        Object.keys(arg)
            .map(function (key) {
                return key + '=' + arg[key];
            })
            .join(', ')
    );
    var dt = now();
    var t_cost = (arg && arg.time) || 10;
    var m_cost = (arg && arg.mem) || 1024;
    var parallelism = (arg && arg.parallelism) || 1;
    var passEncoded = encodeUtf8(arg.pass || 'password');
    var pwd = allocateArray(passEncoded);
    var pwdlen = passEncoded.length;
    var saltEncoded = encodeUtf8(arg.salt || 'somesalt');
    var argon2_type = (arg && arg.type) || 0;
    var salt = allocateArray(saltEncoded);
    var saltlen = saltEncoded.length;
    var hash = Module.allocate(
        new Array((arg && arg.hashLen) || 32),
        'i8',
        Module.ALLOC_NORMAL
    );
    var hashlen = (arg && arg.hashLen) || 32;
    var encodedlen = Module._argon2_encodedlen(
        t_cost,
        m_cost,
        parallelism,
        saltlen,
        hashlen,
        argon2_type
    );
    var encoded = Module.allocate(
        new Array(encodedlen + 1),
        'i8',
        Module.ALLOC_NORMAL
    );
    var secret = 0;
    var secretlen = 0;
    var ad = 0;
    var adlen = 0;
    var version = 0x13;
    var err;
    try {
        var res = Module._argon2_hash_ext(
            t_cost,
            m_cost,
            parallelism,
            pwd,
            pwdlen,
            salt,
            saltlen,
            hash,
            hashlen,
            encoded,
            encodedlen,
            argon2_type,
            secret,
            secretlen,
            ad,
            adlen,
            version
        );
    } catch (e) {
        err = e;
    }
    var elapsed = now() - dt;
    if (res === 0 && !err) {
        var hashArr = [];
        for (var i = hash; i < hash + hashlen; i++) {
            hashArr.push(Module.HEAP8[i]);
        }
        const encodedHash = Module.UTF8ToString(encoded);
        console.log('Encoded: ' + encodedHash);
        console.log(
            'Hash: ' +
            hashArr
                .map(function (b) {
                    return ('0' + (0xff & b).toString(16)).slice(-2);
                })
                .join('')
        );
        console.log('Elapsed: ' + Math.round(elapsed) + 'ms');
        post({ encodedHash: encodedHash, err: null });
    } else {
        try {
            if (!err) {
                err = Module.UTF8ToString(Module._argon2_error_message(res));
            }
        } catch (e) { }
        const errorMessage = 'Error: ' + res + (err ? ': ' + err : '');
        console.log(errorMessage);
        post({ encodedHash: null, err: errorMessage });
    }
    try {
        Module._free(pwd);
        Module._free(salt);
        Module._free(hash);
        Module._free(encoded);
    } catch (e) { }
}

function encodeUtf8(str) {
    return new TextEncoder().encode(str);
}

function allocateArray(arr) {
    return Module.allocate(arr, 'i8', Module.ALLOC_NORMAL);
}

function now() {
    return global.performance ? performance.now() : Date.now();
}
