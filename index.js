
// modules
import { noDataRetrievalDialogue, retrievePasswords, getMasterPassword, mainMenu } from "./src/interactions.js";
import {
    errorPrefix,
    warnPrefix,
    infoPrefix,
    debugPrefix,
    prompt,
    fetchFile,
    saveFile,
    createFile,
    importData,
    decryptData,
    helpMessage,
    parseArgs,
    initTimeout,
    resetTimeout,
    terminate
} from "./src/util.js";


/**
 * @typedef {{ file: string, charset: string, verbose: boolean, outputMethod: "CLIPBOARD" | "STDOUT", help: boolean, passwordVisibility: "HIDDEN" | "MASKED" | "CLEAR", quick: boolean, createFile: string, timeout: number, import: string }} args The command line args
 * @typedef {{ data: data, version: number, checksum: string }} fileContents
 */

/**
 * Runs the program
 */
async function main() {
    // parse argv
    let args;
    try {
        args = parseArgs();
    } catch (e) {
        if (process.argv.find(v => /^-[\w]*v[\w]*/.test(v)) || process.argv.includes("--verbose")) {
            console.log(errorPrefix, "Couldn't parse arguments:", e);
        } else {
            console.log(errorPrefix, "Couldn't parse arguments:", e.message);
        }
        process.exitCode = 1;
        return;
    }

    // help flag
    if (args.help) {
        helpMessage();
        return;
    }

    // create-file flag
    if (args.createFile) {
        createFile(args);
        return;
    }

    // main block
    try {
        // get data if available
        if (args.verbose)
            console.log(debugPrefix, "Fetching file...");
        /**
         * version is set if the file exists
         * forceRehash is true if the hash in the file is invalid
         * dataDamaged is true if the data property contains unparsable data
         * dataCleared is true if the user decided to clear the data because it was damaged
         */
        const { version, checksum: fetchedChecksum, data: encryptedData, forceRehash, dataDamaged, dataCleared } = await fetchFile(args);

        // ask master password
        if (args.verbose)
            console.log(debugPrefix, "Asking for master password...");
        const { password, checksum } = await getMasterPassword(args, fetchedChecksum, forceRehash, version !== null);

        // init timeout counter
        initTimeout(args.timeout * 1000);

        // fix bad data
        // can only be true if a file was loaded
        // no excryption key is needed for this saveFile call, as the data is already encrypted
        if (checksum !== fetchedChecksum || dataCleared) {
            if (args.verbose)
                console.log(debugPrefix, "Saving updated data...");
            saveFile(args, { checksum, data: encryptedData });
        }

        // decrypt data
        const data = await decryptData(args, encryptedData, password, dataDamaged, version !== null, version);

        // import data if flag is set and if the file was loaded (terminates the program)
        if (args.import && version !== null) {
            console.log(infoPrefix, "Importing from", args.import);
            await importData(args, password, data);
            terminate(true);
        }

        // main loop
        await loop(args, data, password);
    } catch (e) {
        if (args.verbose) {
            console.log(errorPrefix, "Fatal Error:", e);
        } else {
            console.log(errorPrefix, "Fatal Error:", e.message);
        }
        terminate(true);
    }
}

/**
 * The main loop
 * @param {args} args
 * @param {data} data The file data
 * @param {string} password The master password
 */
async function loop(args, data, password) {
    while (true) {
        // call interactions
        if (data) {
            await mainMenu(args, data, password);
        } else {
            await retrievePasswords(args, noDataRetrievalDialogue(args), password);
        }

        // allow user to exit gracefully
        const { loop } = await prompt([{
            type: "list",
            name: "loop",
            message: "Do you want to perform another action?",
            choices: [{ name: "Yes", value: true }, { name: "No", value: false }]
        }]);
        if (loop) {
            resetTimeout();
        } else {
            terminate(true);
        }
    }
}

// run program
main();
