
const options = document.getElementById("options");
const lengthLabel = document.getElementById("length-slide-label");
const passwordContainer = document.getElementById("password-container");
const generateButton = document.getElementById("generate");
let passwordText = null;

const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const charset = "!#$%()*,-./0123456789:@ABCDEFGHIJKLMNOPQR^_`abcdefghijklmnopqr|~";

options.addEventListener("submit", async (event) => {
    event.preventDefault();

    generateButton.disabled = "true"

    passwordContainer.innerHTML = 'Generating! Please wait... <button disabled="true">Copy</button>';

    const srvName = event.currentTarget.elements["service-name"].value
    const user = event.currentTarget.elements["username"].value || "null";
    const salt = event.currentTarget.elements["salt"].value;
    const length = Number(event.currentTarget.elements["length-slide"].value);

    const arg = {
        pass: event.currentTarget.elements["password"].value,
        salt: `ASk[Jw,%7/M"~&p9!H|Lfl3FUw{3l;P!${salt}#${user}@${srvName}`,
        time: 20,
        mem: 262144,
        hashLen: length,
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

        const final = encodedHash.split("$").at(-1).split("").slice(0, length);

        for (let i = 0; i < final.length; i++) {
            final[i] = charset[base64.indexOf(final[i])];
        }

        const inputHasChanged = passwordText === "*"
        passwordText = `${salt}# ${user} @ ${srvName} &mdash; <div id="pwtext" class="inline spoiler extended-background" onclick="this.classList.remove('spoiler')">${final.join("")}</div>`;
        passwordContainer.innerHTML = `${inputHasChanged ? "*" : ""}${passwordText} <button onclick="navigator.clipboard.writeText('${final.join("")}')">Copy</button>`;
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
    const worker = new Worker('js/worker.js');
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
