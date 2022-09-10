
// dependencies
import chalk from "chalk";
import arg from "arg";
import argon2 from "argon2";
const { argon2id, hash } = argon2;
import inquirer from "inquirer";
// node apis
import { readFileSync, writeFileSync, existsSync } from "fs";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { cpus, totalmem, freemem } from "os";


export const MEMORY_COST = 1 << 18;
export const TIME_COST = 20;
export const PARALLELISM = 4;

export const MASTER_OPTIONS = {
    type: argon2id,
    hashLength: 32,
    saltLength: 16,
    memoryCost: MEMORY_COST,
    timeCost: TIME_COST,
    parallelism: PARALLELISM
};

export const FILE_VERSION = 1; // expected version of the data file
export const DATA_VERSION = 2; // expected version of the data property in the data file (seperate because the data is encrypted and thus cannot be verified in the same step)

export const defaultInactivityTimeout = 120; // After this amount of milliseconds has passed without any interaction, the app will terminate

export const defaultCharset = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
export const defaultLength = 30;
export const strongPasswordThreshold = 64; // required bits of entropy for a good generated password
export const validJSONPathRegExp = /^(?:\w\:)?(?:[^\\\/]*[\\\/])*(?:[^\\\/]*\.json)$/i;

export const errorPrefix = chalk.red("[") + chalk.redBright("ERROR") + chalk.red("]");
export const warnPrefix = chalk.yellow("[") + chalk.yellowBright("WARN") + chalk.yellow("]");
export const infoPrefix = chalk.rgb(11, 142, 130)("[") + chalk.rgb(38, 226, 208)("INFO") + chalk.rgb(11, 142, 130)("]");
export const debugPrefix = chalk.white("[") + chalk.whiteBright("DEBUG") + chalk.white("]");
export const grayBright = [164, 164, 164];

export const promptRaw = inquirer.createPromptModule();


/**
 * @typedef {{ file: string?, charset: string, verbose: boolean, outputMethod: "CLIPBOARD" | "STDOUT", help: boolean, passwordVisibility: "HIDDEN" | "MASKED" | "CLEAR", quick: boolean, createFile: string?, timeout: number, import: string? }} args The command line args
 * @typedef {{ version: number, checksum: string?, data: data? }} fileContents
 * @typedef {{ version: number, services: {} }} data
 * @typedef {{ key: Buffer, salt: Buffer }} EncryptionSecret
 * @typedef {{ name: string, salt: string, length: number, note: string }} User
 * @typedef {"CUSTOM" | "REGULAR" | "ALPHANUMERIC" | "ALPHANUMERIC_WITH_SPECIAL"} Scheme Password schemes to be possibly used in the future
 */


/**
 * **********
 *     IO
 * **********
 */

// used by fetchFile, saveFile and updateFile
const file = {
    version: null,
    checksum: null,
    data: null // encrypted string
};

/**
 * fetch data if possible and sanity check
 * @param {args} args
 * @returns {Promise<{ version: number?, checksum: string?, data: string?, forceRehash: boolean, dataDamaged: boolean, dataCleared: boolean }>}
 */
export async function fetchFile(args) {
    const noData = {
        checksum: null,
        data: null,
        version: null,
        forceRehash: false,
        dataDamaged: false,
        dataCleared: false
    };

    // if no file was given, return no data
    if (!args.file)
        return noData;

    // load file
    let fileContent = null;
    try {
        fileContent = JSON.parse(readFileSync(args.file, "utf-8")) ?? {};

        // check version integrity
        file.version = fileContent.version ?? null;
        if (file.version !== FILE_VERSION) {
            if (file.version && file.version < FILE_VERSION) {
                console.log(warnPrefix, `File version outdated, updating from ${file.version} to ${FILE_VERSION}`);
                updateFile();
            } else {
                throw new Error(`Cannot read file with version=${file.version}`);
            }
        }
    } catch (e) {
        if (args.verbose) {
            console.log(warnPrefix, `Failed to load file! Continuing without data\n${warnPrefix}`, e);
        } else {
            console.log(warnPrefix, `Failed to load file! Continuing without data\n${warnPrefix} ${e}`);
        }
        return noData;
    }

    // validate data
    file.checksum = fileContent.checksum ?? null; // data.checksum has to be either nullish, or a argon2 hash
    file.data = fileContent.data ?? null; // data.data has to be either nullish, or an object containing service objects
    let forceRehash = false;
    let dataDamaged = false;
    let dataCleared = false;
    // check checksum integrity
    if (file.checksum !== null && !/^\$argon2id\$v=\d+\$m=([1-9]\d*|0),t=([1-9]\d*|0),p=([1-9]\d*|0)\$[A-Za-z0-9+/]*\$[A-Za-z0-9+/]*$/.test(file.checksum)) {
        console.log(`${warnPrefix} Couldn't parse 'checksum', needs to be nullish or an argon2 hash\n${warnPrefix} Password checking has been temporarily disabled`);
        forceRehash = true;
    }
    // check data integrity (24 bytes salt, 24 bytes iv, 16 bytes MAC, n bytes ciphertext)
    if (file.data !== null && !/^[A-Za-z0-9+/]{32}\$[A-Za-z0-9+/]{32}\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]*$/.test(file.data)) {
        console.log(warnPrefix, "Couldn't parse 'data', needs to be nullish or four base 64 strings joined by '$'");
        const { clear } = await prompt([{
            type: "confirm",
            name: "clear",
            message: "Do you want to clear the service data? This will permanently delete registered services"
        }]);
        // enforce either returning null data if it was cleared, or marking the data as damaged, in which case decryptData will return null
        if (clear) {
            file.data = null;
            dataCleared = true;
        } else {
            dataDamaged = true;
        }
    }

    return {
        version: file.version,
        checksum: file.checksum,
        data: file.data,
        forceRehash,
        dataDamaged,
        dataCleared
    };
}

/**
 * Saves data to the local file.
 * If the 'data' property is a data object, {@link initEncryptionKey} needs to have been called beforehand
 * @param {args} args
 * @param {{ version?: number, checksum?: string, data?: string | data? }} contents
 */
export function saveFile(args, contents) {
    if (!encryptionSecret)
        throw new Error("No EncryptionKey initialized");

    if (!file.version)
        throw new Error("Cannot modify file without loading it first");

    // modify file
    const writtenTo = [];
    if (contents.data !== undefined) {
        // contents.data is always either an object to encrypt (has version property), a string thats already encrypted, or null
        if (contents.data?.version) {
            file.data = encryptData(contents.data);
        } else {
            file.data = contents.data;
        }
        writtenTo.push("'data'");
    }
    if (contents.checksum !== undefined) {
        file.checksum = contents.checksum;
        writtenTo.push("'checksum'");
    }
    if (contents.version !== undefined) {
        file.version = contents.version;
        writtenTo.push("'version'");
    }

    // save
    if (args.verbose)
        console.log(debugPrefix, `Writing to ${writtenTo.join(", ")} properties of file...`);
    writeFileSync(args.file, JSON.stringify(file));
}

/**
 * Creates a file at the location of args.createFile
 * @param {args} args
 */
export function createFile(args) {
    const fileContents = JSON.stringify(newFile());
    const path = getSafePathForNewJsonFile(args.createFile);
    if (path) {
        writeFileSync(path, fileContents);
        console.log(infoPrefix, `Created new data file at ${path}`);
    } else {
        console.log(errorPrefix, "The directory you specified does not exist");
    }
}

/**
 * Import an export file into the data
 * @param {args} args
 * @param {string} password
 * @param {data?} data
 */
export async function importData(args, password, data) {
    // init encryption
    await initEncryptionKey(password, false);

    // import new data
    let imported;
    try {
        const fileContents = JSON.parse(readFileSync(args.import, "utf-8")) ?? {};

        // make sure data is ok
        validateData(fileContents);

        imported = fileContents;
    } catch (e) {
        if (args.verbose) {
            console.log(errorPrefix, `Failed to load import! Terminating\n${errorPrefix}`, e);
        } else {
            console.log(errorPrefix, `Failed to load import! Terminating\n${errorPrefix} ${e}`);
        }
        return;
    }

    // Ask user for operation; if data is null auto select "overwrite", ask for confirmation if "overwrite" is the selected mode
    const { mode = "overwrite", confirmed } = await prompt([
        {
            type: "list",
            name: "mode",
            message: "Do you want to add this data to the existing data, or overwrite it with the imported data?",
            choices: [{ name: "Add to existing data", short: "add", value: "add" }, { name: "Overwrite data with imported data", short: "overwrite", value: "overwrite" }],
            when: data !== null
        },
        {
            type: "confirm",
            name: "confirmed",
            message: "Importing and overwriting will permanently delete all current data from your current data file (except for the master password hash). Are you sure?",
            when: ans => ans.mode !== "add"
        }
    ]);

    // Execute
    let importedServices = 0;
    let importedUsers = 0;
    if (mode === "add") {
        for (const { service, name } of Object.getOwnPropertyNames(imported.services).map(v => ({ service: imported.services[v], name: v }))) {
            const registeredService = data.services[name];
            if (registeredService) {
                for (const user of service) {
                    if (registeredService.find(v => v.name === user.name)) {
                        console.log(warnPrefix, `${user.name} is already registered, skipping`);
                    } else {
                        registeredService.push(user);
                        importedUsers++;
                    }
                }
            } else {
                data.services[name] = service;
                importedUsers += service.length;
                importedServices++;
            }
        }
    } else if (confirmed) {
        data = {
            version: imported.version,
            services: imported.services
        };
        importedServices = Object.getOwnPropertyNames(imported.services).length;
        importedUsers = Object.getOwnPropertyNames(imported.services).map(v => imported.services[v]).flat().length;
    } else {
        return; // if the user didn't confirm, just exit
    }

    saveFile(args, { data });

    console.log(infoPrefix, `Successfully imported ${importedServices} services and ${importedUsers} users from`, args.import);
}

/**
 * Validate that data is good and fix if possible
 * @param {data} data
 */
function validateData(data) {
    // make sure data has correct version
    if (data.version !== DATA_VERSION) {
        if (data.version && data.version < DATA_VERSION) {
            console.log(warnPrefix, `Data version outdated, updating from ${data.version} to ${DATA_VERSION}`);
            updateData(data);
        } else {
            throw new Error(`Cannot read data with version=${data.version}`);
        }
    }

    // throw if data is not healthy
    if (!data.services || typeof data.services !== "object")
        throw new Error("'services' is either missing or not an object");
    for (const { service, name } of Object.getOwnPropertyNames(data.services).map(v => ({ service: data.services[v], name: v }))) {
        if (!Array.isArray(service))
            throw new Error(`services.${name} has to be an Array`);

        for (let i = 0; i < service.length; i++) {
            if (!service[i].name)
                throw new Error(`services.${name}[${i}] has no name`);
            if ((service[i].salt ?? null) === null)
                throw new Error(`services.${name}[${i}] (${service[i].name}) has no salt`);
            if (!validateLength(service[i].length))
                throw new Error(`services.${name}[${i}] (${service[i].name}) has an invalid length`);
            if ((service[i].note ?? null) === null)
                throw new Error(`services.${name}[${i}] (${service[i].name}) has no note`);
        }
    }
}

/**
 * Updates the file to the current version
 */
function updateFile() {
    switch (file.version) {
        case 1:
        default:
            file.version = FILE_VERSION;
    }
}

/**
 * Modifies data to reflect the current version
 * @param {data} data
 */
function updateData(data) {
    switch (data.version) {
        case 1:
            for (const { service, name } of Object.getOwnPropertyNames(data.services).map(v => ({ service: data.services[v], name: v }))) {
                service.forEach(v => {
                    if (!(validateLength(v.length) === true)) {
                        console.log(warnPrefix, `data.services.${name}.${v.name} has an invalid length. Changing from ${v.length} to 131072`);
                        v.length = 131072;
                    }
                });
            }
        default:
            data.version = DATA_VERSION;
    }
}


/**
 * **********
 *   CRYPTO
 * **********
 */

/**
 * The encryption key used in {@link encryptData}
 * @type {EncryptionSecret?}
 */
let encryptionSecret = null;

/**
 * decrypts the ciphertext stored in data using the master password
 * @param {args} args
 * @param {string} encrypted the ciphertext along with the key salt and IV
 * @param {string} password
 * @param {boolean} dataDamaged whether the data is parsable
 * @param {boolean} hasFile whether a file was loaded
 * @param {number} fileVersion FILE_VERSION of the file
 * @returns {Promise<data?>}
 */
export async function decryptData(args, encrypted, password, dataDamaged, hasFile, fileVersion) {
    const errMessage = "Cannot decrypt damaged data, continuing without data.";

    // fail if data cannot be parsed
    if (dataDamaged || !hasFile) {
        if (dataDamaged)
            console.log(errorPrefix, errMessage);
        return null;
    }

    // if the file has data === null, return a fresh data object
    if (!encrypted)
        return newData();

    const [salt, iv, authTag, ciphertext] = encrypted.split("$");
    // generate key
    const key = await cipherKey(password, Buffer.from(salt, "base64"));
    // decipher
    try {
        const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64")).setAuthTag(Buffer.from(authTag, "base64"));
        const cleartext = decipher.update(ciphertext, "base64", "utf-8") + decipher.final("utf-8");

        const data = JSON.parse(cleartext);

        // make sure data is ok
        validateData(data);

        return data;
    } catch (e) {
        // fail if data cannot be decrypted
        if (args.verbose) {
            console.log(errorPrefix, errMessage, e);
        } else {
            console.log(errorPrefix, errMessage);
        }
        return null;
    }
}

/**
 * encrypts cleartext into a ciphertext to be stored in data, padding is stripped
 * @param {data} data The data to encrypt
 * @returns {string}
 */
function encryptData(data) {
    const iv = randomBytes(24);
    const cipher = createCipheriv("aes-256-gcm", encryptionSecret.key, iv);
    const ciphertext = cipher.update(JSON.stringify(data), "utf-8", "base64") + cipher.final("base64").split("=")[0];
    const authTag = cipher.getAuthTag().toString("base64").split("=")[0];
    const ivEncoded = iv.toString("base64");
    const saltEncoded = encryptionSecret.salt.toString("base64");
    return [saltEncoded, ivEncoded, authTag, ciphertext].join("$");
}

/**
 * Generates the passwords for the selected users
 * @param {string} service
 * @param {User[]} users
 * @param {string} masterPassword
 * @param {string} charset
 * @param {number} parallelHashes
 * @returns {Promise<string[]>}
 */
export async function generatePasswords(service, users, masterPassword, charset, parallelHashes) {
    const queue = new Array(Math.ceil(users.length / parallelHashes)).fill(null).map((_, i) => users.slice(parallelHashes * i, parallelHashes * (i + 1)));
    const generated = [];

    for (const item of queue) {
        const hashes = await Promise.all(item.map(user => hash(masterPassword, {
            type: argon2id,
            salt: Buffer.from(`ASk[Jw,%7/M"~&p9!H|Lfl3FUw{3l;P!${user.salt}#${user.name}@${service}`),
            hashLength: getRequiredHashBytes(user, charset),
            memoryCost: MEMORY_COST,
            timeCost: TIME_COST,
            parallelism: PARALLELISM,
            raw: true
        }).then(v => getPasswordFromBuffer(v, charset, user))));
        generated.push(...hashes);
        resetTimeout();
    }

    return generated;
}

/**
 * Generates a 256 bit cipher key from a password
 * @param {string} password
 * @param {Buffer} salt
 * @returns {Promise<Buffer>}
 */
export function cipherKey(password, salt) {
    return hash(password, {
        type: argon2id,
        memoryCost: MEMORY_COST,
        timeCost: TIME_COST,
        parallelism: PARALLELISM,
        salt: salt,
        hashLength: 32,
        raw: true
    });
}

/**
 * Sets the encryptionSecret to a new key. Needs to be called once before data can be encrypted in the {@link saveFile} function
 * @param {string} password
 * @param {boolean} force whether to force generation, even if a key already exists
 */
export async function initEncryptionKey(password, force = false) {
    if (!encryptionSecret || force) {
        const salt = randomBytes(24);
        encryptionSecret = {
            key: await cipherKey(password, salt),
            salt: salt
        };
    }
}


/**
 * ***********
 *   GENERIC
 * ***********
 */

/**
 * Displays a help message
 */
export function helpMessage() {
    console.log(
        `${infoPrefix} evacora v1.2.0\n` +
        `${infoPrefix}\n` +
        `${infoPrefix} A stateless password manager\n` +
        `${infoPrefix}\n` +
        `${infoPrefix} Available options:\n` +
        `${infoPrefix} --help, -h               display this list\n` +
        `${infoPrefix} --file, -f <path>        specify a file containing registered accounts\n` +
        `${infoPrefix} --create-file <path>     create a data file at the specified location\n` +
        `${infoPrefix} --import <path>          import data from an exported file, has to be used in combination with --file\n` +
        `${infoPrefix} --charset, -m <charset>  specify up to 64 characters to be used in the passwords\n` +
        `${infoPrefix} --verbose, -v            log verbosely\n` +
        `${infoPrefix} --copy, -c               copy the passwords into the clipboard instead of using STDOUT\n` +
        `${infoPrefix} --show-password, -s      repeatable; specify whether the password is hidden, masked or clear\n` +
        `${infoPrefix} --quick, -q              skip confirm requests on destructive actions\n` +
        `${infoPrefix} --timeout, -t <number>   specify a number of seconds of inactivity until automatic termination`
    );
}

/**
 * Parses argv args
 * @returns {args}
 */
export function parseArgs() {
    let args;
    args = arg(
        {
            // args
            "--copy": Boolean,
            "--file": String,
            "--help": Boolean,
            "--charset": String,
            "--quick": Boolean,
            "--show-password": arg.COUNT,
            "--timeout": Number,
            "--verbose": Boolean,
            "--create-file": String,
            "--import": String,

            // alias
            "-c": "--copy",
            "-f": "--file",
            "-h": "--help",
            "-m": "--charset",
            "-q": "--quick",
            "-s": "--show-password",
            "-t": "--timeout",
            "-v": "--verbose"
        },
        {
            permissive: false,
            argv: process.argv.slice(2),
        }
    );

    args = {
        file: args["--file"] || null,
        charset: args["--charset"] ?? defaultCharset,
        verbose: args["--verbose"] ?? false,
        outputMethod: (args["--copy"] ?? false) ? "CLIPBOARD" : "STDOUT",
        passwordVisibility: (args["--show-password"] ?? 0) === 0 ? "HIDDEN" : args["--show-password"] === 1 ? "MASKED" : "CLEAR",
        help: args["--help"] ?? false,
        createFile: args["--create-file"] || null,
        import: args["--import"] || null,
        quick: args["--quick"] ?? false,
        timeout: args["--timeout"] ?? defaultInactivityTimeout
    };

    // append '.json' to the end of --file path if not there
    if (args.file && !/\.json$/i.test(args.file))
        args.file += ".json";

    // if present, --file has to point to a valid .json file
    if (args.file && !validJSONPathRegExp.test(args.file))
        throw new Error("The --file option has to be a path pointing to a JSON file");

    // append '.json' to the end of --import path if not there
    if (args.import && !/\.json$/i.test(args.import))
        args.import += ".json";

    // if present, --import has to point to a valid .json file
    if (args.import && !validJSONPathRegExp.test(args.import))
        throw new Error("The --import option has to be a path pointing to a JSON file");

    // --import needs --file
    if (args.import && !args.file)
        throw new Error("You cannot import without also specifying --file");

    // append '.json' to the end of --create-file path if not there
    if (args.createFile && !/\.json$/i.test(args.createFile))
        args.createFile += ".json";

    // if present, --createFile has to point to a valid .json file
    if (args.createFile && !validJSONPathRegExp.test(args.createFile))
        throw new Error("The --create-file option has to be a path pointing to a JSON file");

    // --file and --create-file are mutually exclusive
    if (args.file && args.createFile)
        throw new Error("The --file and --create-file options are mutually exclusive");

    // sort charset and remove duplicate characters
    args.charset = args.charset.split("").sort().filter((v, i, a) => a[i - 1] !== v).join("");

    // charset has to contain 2 or more characters
    if (args.charset.length < 2)
        throw new Error("The charset has to contain at least 2 unique characters");

    // timeout may not be negative
    if (!(args.timeout > 0))
        throw new Error("The inactivity timeout has to be positive");

    return args;
}

/**
 * Returns the required amount of bytes for a password hash
 * @param {User} user
 * @param {string} charset
 */
function getRequiredHashBytes(user, charset) {
    return Math.max(user.length, Math.ceil(Math.log2(charset.length) * user.length / 8));
}

/**
 * Returns the generated password from a buffer
 * This is done by effectively just writing out
 * the most significant bits of the buffer in a
 * base equal to the length of the used charset
 * @param {Buffer} hash
 * @param {string} charset
 * @param {User} user
 */
function getPasswordFromBuffer(hash, charset, user) {
    // convert hash to BigInt; the bigint will have exactly as many bits as required to fit the characters
    let number = 0n;
    const requiredBytes = Math.log2(charset.length) * user.length / 8;
    for (let i = 0; i < requiredBytes; i++) {
        number = (number << 8n) + BigInt(hash.at(i));
    }
    number >>= BigInt(Math.floor(8 - (requiredBytes - Math.ceil(requiredBytes - 1)) * 8)); // truncate unneeded bits

    // convert to base charset.length
    const characters = [];
    const charsetLength = BigInt(charset.length);
    for (let i = 0; i < user.length; i++) {
        characters.push(charset[Number(number % charsetLength)]);
        number /= charsetLength;
    }

    return characters.reverse().join("");
}

/**
 * returns the maximum amount of hashes running in parallel given the currently available resources
 * @returns {Promise<number>}
 */
export async function getMaxParallelHashes() {
    // max parallel hashes while keeping ram usage below 80%
    const memorySlotsAvailable = Math.max(1, Math.floor((freemem() - 0.2 * totalmem()) / MEMORY_COST / 1024));
    // max parallel hashes while only using cores with < 25% usage
    const testStart = cpus();
    await sleep(100);
    const cpuSlotsAvailable = Math.max(1, Math.floor(cpus().map((v, i) =>
        (v.times.idle - testStart[i].times.idle) /
        (v.times.idle - testStart[i].times.idle +
            v.times.irq - testStart[i].times.irq +
            v.times.nice - testStart[i].times.nice +
            v.times.sys - testStart[i].times.sys +
            v.times.user - testStart[i].times.user))
        .filter(v => v >= 0.75).length / PARALLELISM));
    return Math.min(cpuSlotsAvailable, memorySlotsAvailable);
}

/**
 * The data of a new file
 * @returns {fileContents}
 */
export function newFile() {
    return {
        version: FILE_VERSION,
        checksum: null,
        data: null
    };
}

/**
 * The data of a new data object
 * @returns {data}
 */
export function newData() {
    return {
        version: DATA_VERSION,
        services: {}
    };
}

/**
 * returns the entropy of a password given a length and a charset containing distinct characters
 * @param {string} charset
 * @param {number} length the password length
 * @returns {number} The entropy in bits
 */
export function generatedPasswordEntropy(charset, length) {
    return Math.log2(charset.length) * length;
}

/**
 * Returns a path to a location that isn't already used
 * @param {string} path
 * @returns {string?} A safe path to a file that doesn't exist yet, null if the directory doesn't exist
 */
export function getSafePathForNewJsonFile(path) {
    const directory = path.slice(0, Math.max(0, path.lastIndexOf("/"), path.lastIndexOf("\\"))) || ".";
    if (existsSync(path)) {
        let i = 1;
        const pathWithoutExtension = path.slice(0, path.lastIndexOf(".json"));
        while (existsSync(pathWithoutExtension + ` (${i}).json`))
            i++;
        return pathWithoutExtension + ` (${i}).json`;
    } else if (existsSync(directory)) {
        return path;
    } else {
        return null;
    }
}


/**
 * Prompts the user the questions and returns the answers
 * @param {any[]} questions The questions to prompt
 * @param {any} initialAnswers The initual answer hash
 */
export async function prompt(questions, initialAnswers) {
    let ans = initialAnswers;
    for (const q of questions) {
        ans = await promptRaw([q], ans);
        resetTimeout();
    }
    return ans;
}

let timeoutMs = null;
let timeout = null;
/**
 * Initialize a termination timeout
 * @param {number} milliseconds
 */
export function initTimeout(milliseconds) {
    timeoutMs = milliseconds;
    timeout = setTimeout(terminate, milliseconds);
}

/**
 * Reset the timeout to the max counter
 */
export function resetTimeout() {
    if (timeoutMs) {
        clearTimeout(timeout);
        timeout = setTimeout(terminate, timeoutMs);
    }
}

/**
 * terminate the process
 * this should not ever terminate during a write process
 * because writes are sync and block the thread
 * @param {boolean} userInduced whether the user ordered this termination
 */
export function terminate(userInduced = false) {
    if (!userInduced) {
        console.log("\n");
        console.log(infoPrefix, "Terminating process due to inactivity.");
    }
    process.exit(0);
}

/**
 * resolves after ms milliseconds
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Rejects all passwords that are not between 4 and 10m characters long
 * @param {number} length
 */
export function validateLength(length) {
    const min = 4;
    const max = 131072;
    return length >= min && length <= max && Number.isInteger(length) ? true : `Length has to be an integer between ${min} and ${max}`;
}
