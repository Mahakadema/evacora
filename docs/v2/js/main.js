
const options = document.getElementById("options");
const lengthLabel = document.getElementById("length-slide-label");
const passwordContainer = document.getElementById("password-container");
const generateButton = document.getElementById("generate");
let passwordText = null;
let generatedPassword = null;

const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const defaultRegularCharset = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
const alphanumericCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const alphanumericWithSpecialUsedCharacter = "!";
const numericCharset = "0123456789";

function getRequiredHashBytes(scheme, length, regularCharset) {
    switch (scheme) {
        case "REGULAR":
            return Math.ceil(Math.log2(regularCharset.length) * 0.125 * length) + 4;
        case "ALPHANUMERIC":
            return Math.ceil(Math.log2(alphanumericCharset.length) * 0.125 * length) + 4;
        case "ALPHANUMERIC_WITH_SPECIAL":
            return Math.ceil(Math.log2(alphanumericCharset.length) * 0.125 * (length - 1)) + Math.ceil(Math.log2(length) / 8) + 8;
        case "NUMERIC":
            return Math.ceil(Math.log2(numericCharset.length) * 0.125 * length) + 4;
    }
    throw new Error("Unknown scheme: " + scheme);
}

function getPasswordFromBuffer(buff, regularCharset, scheme, length) {
    switch (scheme) {
        case "REGULAR":
            return bigintToCharset(bufferToBigint(buff), regularCharset, length);
        case "ALPHANUMERIC":
            return bigintToCharset(bufferToBigint(buff), alphanumericCharset, length);
        case "ALPHANUMERIC_WITH_SPECIAL":
            const lengthBytes = Math.ceil(Math.log2(length) / 8) + 4;
            const baseString = bigintToCharset(bufferToBigint(buff, lengthBytes), alphanumericCharset, length - 1);
            const specialCharIndex = Number(bufferToBigint(buff, 0, lengthBytes) % BigInt(length));
            return baseString.slice(0, specialCharIndex) + alphanumericWithSpecialUsedCharacter + baseString.slice(specialCharIndex)
        case "NUMERIC":
            return bigintToCharset(bufferToBigint(buff), numericCharset, length);
        default:
            throw new Error("Unknown scheme: " + scheme);
    }
}

function bufferToBigint(buff, start = 0, end = buff.length) {
    let number = 0n;
    for (let i = start; i < end; i++) {
        number = (number << 8n) + BigInt(buff[i]);
    }
    return number;
}

function bigintToCharset(int, charset, length) {
    /**
     * This way of converting the top n bits to base
     * m has a very slight bias towards characters
     * lower in the charset, this reduces the entropy
     * by a fraction of a bit
     */
    // convert to base charset.length
    const characters = [];
    const charsetLength = BigInt(charset.length);
    for (let i = 0; i < length; i++) {
        characters.push(charset[Number(int % charsetLength)]);
        int /= charsetLength;
    }

    return characters.join("");
}

function base64ToBuffer(b64) {
    const buff = new Uint8Array(Math.floor(b64.length * 0.75))
    for (let i = 0; i < buff.length / 3; i++) {
        const n0 = base64.indexOf(b64[4 * i]);
        const n1 = base64.indexOf(b64[4 * i + 1]);
        const n2 = b64[4 * i + 2] ? base64.indexOf(b64[4 * i + 2]) : null;
        const n3 = b64[4 * i + 3] ? base64.indexOf(b64[4 * i + 3]) : null;
        buff[3 * i] = (n0 << 2) + (n1 >> 4);
        if (n2)
            buff[3 * i + 1] = (n1 << 4) % 256 + (n2 >> 2);
        if (n3)
            buff[3 * i + 2] = (n2 << 6) % 256 + n3;
    }
    return buff;
}

options.addEventListener("submit", async (event) => {
    event.preventDefault();

    generateButton.disabled = "true"

    passwordContainer.innerHTML = 'Generating! Please wait... <button disabled="true">Copy</button>';

    const service = event.currentTarget.elements["service-name"].value
    const user = event.currentTarget.elements["username"].value || "null";
    const salt = event.currentTarget.elements["salt"].value;
    const scheme = event.currentTarget.elements["scheme"].value;
    const length = Number(event.currentTarget.elements["length-slide"].value);
    const master = event.currentTarget.elements["password"].value;

    const arg = {
        pass: master,
        salt: new Uint8Array(await crypto.subtle.digest("sha-256", (new TextEncoder()).encode(`${salt},${length}#${user}@${service}:${scheme}3.14159265358979323846264338327950`))),
        time: 20,
        mem: 1 << 18,
        hashLen: getRequiredHashBytes(scheme, length, defaultRegularCharset),
        parallelism: 4,
        type: 2
    };

    calcWorker(arg, (encodedHash, err) => {
        generateButton.disabled = false;

        if (err) {
            console.error(err);
            passwordContainer.innerHTML = "Failed to generate password: " + err + ' <button disabled="true">Copy</button>';
            return;
        }

        const final = getPasswordFromBuffer(base64ToBuffer(encodedHash.split("$").at(-1).split("")), defaultRegularCharset, scheme, length);

        const inputHasChanged = passwordText === "*";
        passwordText = `${salt}# ${user} @ ${service} &mdash; <div id="pwtext" class="inline spoiler extended-background" onclick="this.classList.remove('spoiler')">${final.split("&").join("&amp;").split("<").join("&lt;")}</div>`;
        passwordContainer.innerHTML = `${inputHasChanged ? "*" : ""}${passwordText} <button onclick="navigator.clipboard.writeText(generatedPassword)">Copy</button>`;
        generatedPassword = final;
    });
});

options.addEventListener("input", (event) => { 
    event.preventDefault();

    if (generateButton.disabled) {
        passwordText = "*";
    } else {
        passwordContainer.innerHTML = `${passwordText ? "*" + passwordText : "No password generated yet"} <button disabled="true">Copy</button>`;
    }

    const elements = Array.from(event.currentTarget.elements);

    elements.forEach(v => {
        if (v.type === "range")
            lengthLabel.innerHTML = "Length: " + v.value
    });
});

// following code from https://github.com/antelle/argon2-browser, modified, MIT
// https://raw.githubusercontent.com/antelle/argon2-browser/master/LICENSE

function loadScript(src, onload, onerror) {
    var el = document.createElement('script');
    el.src = src;
    el.onload = onload;
    el.onerror = onerror;
    document.body.appendChild(el);
}

function calcWorker(arg, cb) {
    const worker = new Worker('../common/js/worker.js');
    worker.method = "simd";
    var loaded = false;
    worker.onmessage = function (e) {
        if (!loaded) {
            loaded = true;
            worker.postMessage({ calc: "simd", arg: arg });
        }
        if (e.data.encodedHash !== undefined) {
            cb(e.data.encodedHash, e.data.err);
        }
    };
}
