
// dependencies
import inquirer from "inquirer";
import chalk from "chalk";
import clipboardy from "clipboardy";
const { write } = clipboardy;
import argon2 from "argon2";
const { hash, verify, needsRehash } = argon2;
// node apis
import { writeFileSync } from "fs";
// modules
import {
    MASTER_OPTIONS,
    defaultLength,
    strongPasswordThreshold,
    errorPrefix,
    warnPrefix,
    infoPrefix,
    debugPrefix,
    grayBright,
    prompt,
    saveFile,
    generatePasswords,
    initEncryptionKey,
    getMaxParallelHashes,
    generatedPasswordEntropy,
    resetTimeout,
    validateLength,
    getSafePathForNewJsonFile,
    terminate,
    sleep
} from "./util.js";


/**
 * @typedef {{ file: string, charset: string, verbose: boolean, outputMethod: "CLIPBOARD" | "STDOUT", help: boolean, passwordVisibility: "HIDDEN" | "MASKED" | "CLEAR", quick: boolean, createFile: string, timeout: number, import: string }} args The command line args
 * @typedef {{ version: number, services: {} }} data
 * @typedef {{ password: string, checksum: string }} master
 */

// --------<I Am Division Line>--------
const divisionLine = new inquirer.Separator(chalk.rgb(...grayBright)("━━━━━━━━"));
const exitOption = {
    name: "Exit",
    short: "exit",
    value: "__exit"
};

// used when no file is provided
function noDataRetrievalDialogue() {
    return [
        {
            type: "input",
            name: "service",
            message: "Service Name",
            validate: inp => inp ? true : "Service Name cannot be empty"
        },
        {
            type: "input",
            name: "__user",
            message: "Username",
            filter: (inp, ans) => {
                ans.users = [{ name: inp || "null", salt: null, length: null, note: "" }];
                return inp || "null";
            }
        },
        {
            type: "input",
            name: "__salt",
            message: "Salt",
            suffix: " (optional)",
            filter: (inp, ans) => { ans.users[0].salt = inp; return inp; } // Set salt for all users without salt
        },
        {
            type: "input",
            name: "__length",
            message: "Length",
            default: defaultLength,
            validate: inp => validateLength(Number(inp)),
            filter: (inp, ans) => validateLength(Number(inp)) === true ? (ans.users[0].length = Number(inp)) || inp : inp // Set length for all users without valid length
        }
    ];
}

// Used in the password generator if data is provided
function hasDataRetrievalDialogue(services) {
    return [
        {
            type: "list",
            name: "service",
            message: "Service Name",
            choices: serviceChoiceList(services),
            filter: (inp, ans) => {
                if (services[inp].length === 0) {
                    ans.users = [{ name: "null", salt: "", length: defaultLength, note: "", isDefault: true }];
                } else if (services[inp].length === 1) {
                    ans.users = services[inp]; // input may not be tampered with
                }
                return inp;
            }
        },
        {
            type: "list",
            name: "users",
            message: "User",
            askAnswered: true,
            when: ans => {
                if (ans.users?.[0].isDefault)
                    return console.log(infoPrefix, "Service has no users, using default user");
                if (ans.users?.length === 1)
                    return console.log(infoPrefix, "Service only has one user, using it");
                return true;
            },
            choices: ans => {
                const choices = userChoiceList(services[ans.service], false);
                return [{ name: "All", value: userChoiceList(services[ans.service], false).map(v => v.value[0]) }].concat(choices);
            }
        }
    ];
}

/**
 * runs the interaction to generate passwords
 * @param {args} args
 * @param {{}[]} questions The questions to ask in this interaction
 * @param {string} masterPassword
 */
async function retrievePasswords(args, questions, masterPassword) {
    // ask questions
    // Remember: input may not be modified as it can contain objects from the data file
    const input = await prompt(questions);
    resetTimeout()

    // determine how many hashes to run in parallel
    const maxParallelHashes = input.users.length === 1 ? 1 : await getMaxParallelHashes();

    // log options
    if (args.verbose) {
        console.log(`\n${debugPrefix} Options:\n` +
            `${debugPrefix} file: ${chalk.greenBright(args.file)}\n` +
            `${debugPrefix} charset: ${chalk.greenBright(args.charset)}\n` +
            `${debugPrefix} service name: ${chalk.greenBright(input.service)}\n` +
            `${debugPrefix} password: ${chalk.greenBright(args.passwordVisibility === "HIDDEN" ? "[hidden]" : args.passwordVisibility === "MASKED" ? "*".repeat(masterPassword.length) : masterPassword)}\n` +
            `${debugPrefix} users:${input.users.reduce((p, c) => p + `\n${debugPrefix}   ${chalk.greenBright(c.salt.padStart(Math.max(...input.users.map(v => v.salt.length))))} # ${chalk.greenBright(c.name)} {${chalk.greenBright(c.length)}}`, "")}\n` +
            `${debugPrefix} maximum parallel hashes: ${chalk.greenBright(maxParallelHashes)}\n` +
            `${debugPrefix} output method: ${chalk.greenBright(args.outputMethod)}`);
    }

    // check generated password strength
    const minimalGeneratedEntropy = generatedPasswordEntropy(args.charset, Math.min(...input.users.map(v => v.length)));
    if (minimalGeneratedEntropy < strongPasswordThreshold)
        console.log(`${warnPrefix} One of the passwords you are generating only has ${minimalGeneratedEntropy} bits of entropy.\n${warnPrefix} Generating a longer password or using a larger charset is recommended.`);

    // generate passwords
    const generatedPasswords = await generatePasswords(input.service, input.users, masterPassword, args.charset, maxParallelHashes);

    // out
    switch (args.outputMethod) {
        case "CLIPBOARD":
            const content = generatedPasswords.join("\n");
            write(content);
            console.log(infoPrefix, "Copied to clipboard!");

            await sleep(15000);

            write("null");
            console.log(infoPrefix, "Deleted from clipboard!");
            break;
        case "STDOUT":
            const saltLength = Math.max(...input.users.map(v => v.salt.length));
            const userLength = Math.max(...input.users.map(v => v.name.length));
            const passLength = Math.max(...generatedPasswords.map(v => v.length));
            const passwords = generatedPasswords.map(v => chalk.redBright(v.padEnd(passLength)));
            const salts = input.users.map(v => chalk.rgb(...grayBright)(v.salt.padStart(saltLength)));
            const users = input.users.map(v => chalk.white(v.name.padEnd(userLength)));
            const notes = input.users.map(v => chalk.rgb(...grayBright)(v.note));
            console.log(`\n${infoPrefix} [${chalk.cyan(input.service)}]`);
            for (let i = 0; i < input.users.length; i++)
                console.log(`${infoPrefix} ${salts[i]} ${chalk.gray("#")} ${users[i]} ${passwords[i]} ${notes[i]}`);
            break;
    }
    console.log();
}

/**
 * Retrieves the master password from the user
 * @param {args} args 
 * @param {string?} checksum 
 * @param {boolean} forceRehash True if the hash of the password is invalid
 * @param {boolean} hasFile True if a data file was loaded
 * @returns {Promise<master>}
 */
async function getMasterPassword(args, checksum, forceRehash, hasFile) {
    // ask master password
    let password = null;
    while (!password) {
        const { password: answeredPassword } = await prompt([{
            type: args.passwordVisibility === "CLEAR" ? "input" : "password",
            name: "password",
            message: "Master Password",
            mask: args.passwordVisibility === "MASKED" ? "*" : null,
            /**
             * TODO: integrate the password check back into the promp once async validators work
             */
            // validate: async inp => checksum === null || forceRehash ? true : (await verify(checksum, inp, MASTER_OPTIONS)) ? true : "Password Incorrect"
        }]);
        if (checksum === null || forceRehash || await verify(checksum, answeredPassword, MASTER_OPTIONS)) {
            password = answeredPassword;
        } else {
            console.log(errorPrefix, "Password incorrect!");
        }
    }

    // check whether checksum needs a rehash
    if (forceRehash || (checksum !== null && needsRehash(checksum, MASTER_OPTIONS))) {
        checksum = await hash(password, MASTER_OPTIONS);
        console.log(infoPrefix, "Your master password has been rehashed and password checking has been reenabled");
    }

    // generate checksum if no checksum was passed
    if (checksum === null && hasFile) {
        checksum = await hash(password, MASTER_OPTIONS);
        console.log(infoPrefix, "Password registered! Password checking has been enabled");
    }

    /**
     * Has the responsibility to only change checksum if hasFile is true
     * (currently solved because forceRehash is false and checksum is null when hasFile === false)
     */
    return {
        checksum,
        password
    };
}

// main menu
const passwordOption = {
    name: "Get passwords",
    short: "passwords",
    value: "passwords"
};
const servicesOption = {
    name: "Edit data",
    short: "edit",
    value: "edit"
};
const exportOption = {
    name: "Export data",
    short: "export",
    value: "export"
}
const passwordBadOption = new inquirer.Separator(chalk.redBright(`${chalk.gray("Get passwords")} ${chalk.redBright("(No services registered)")}`));

/**
 * Main menu with data
 * @param {args} args 
 * @param {data} data 
 * @param {string} password 
 */
async function mainMenu(args, data, password) {
    const { input } = await prompt([
        {
            type: "list",
            name: "input",
            message: "What do you want to do?",
            choices: _ => (Object.getOwnPropertyNames(data.services).length > 0 ? [passwordOption, servicesOption] : [passwordBadOption, servicesOption])
                .concat([exportOption, divisionLine, exitOption])
        }
    ]);
    resetTimeout();
    switch (input) {
        case "passwords":
            await retrievePasswords(args, hasDataRetrievalDialogue(data.services), password);
            break;
        case "edit":
            await editData(args, data, password);
            break;
        case "export":
            await exportData(args, data);
            break;
        case "__exit":
            terminate(true);
    }
}

// main editing menu
const addServiceOption = {
    name: "Add a service",
    short: "add service",
    value: "add"
};
const removeServiceOption = {
    name: "Remove a service",
    short: "remove",
    value: "remove"
};
const editServiceOption = {
    name: "Manage a service's users",
    short: "edit",
    value: "edit"
};
const resetPwOption = {
    name: "Change the master password",
    short: "change password",
    value: "resetPW"
}
const removeServiceBadOption = new inquirer.Separator(`${chalk.gray("Remove a service")} ${chalk.redBright("(No services registered)")}`);
const editServiceBadOption = new inquirer.Separator(`${chalk.gray("Manage a service's users")} ${chalk.redBright("(No services registered)")}`);

/**
 * Menu for editing data
 * @param {args} args 
 * @param {data} data
 * @param {string} password
 */
async function editData(args, data, password) {
    // initialize encryption key to allow for data storage
    await initEncryptionKey(password, false);

    // interaction
    const { input } = await prompt([{
        type: "list",
        name: "input",
        message: "What do you want to do?",
        choices: _ => [addServiceOption]
            .concat(Object.getOwnPropertyNames(data.services).length > 0 ? [removeServiceOption, editServiceOption] : [removeServiceBadOption, editServiceBadOption])
            .concat([resetPwOption, divisionLine, exitOption])
    }]);
    resetTimeout();
    switch (input) {
        case "add":
            await addService(args, data);
            break;
        case "remove":
            await removeService(args, data);
            break;
        case "edit":
            await editService(args, data);
            break;
        case "resetPW":
            await resetMaster(args, data);
            break;
        case "__exit":
            return;
    }
}

/**
 * Menu for adding a service
 * @param {args} args 
 * @param {data} data 
 */
async function addService(args, data) {
    console.log();
    const { input, jumpAddUser } = await prompt([
        {
            type: "input",
            name: "input",
            message: "What is your service name?",
            validate: inp => data.services[inp] ? "That service already exists" : inp === "__exit" ? "That service name is not allowed" : true
        },
        {
            type: "list",
            name: "jumpAddUser",
            message: "Do you want to add a user to this service",
            choices: [{ name: "Yes", value: true }, { name: "No", value: false }]
        }
    ]);
    resetTimeout();
    data.services[input] = [];
    saveFile(args, { data });
    if (jumpAddUser)
        await addUser(args, data, data.services[input]);
}

/**
 * Menu for deleting a service
 * @param {args} args 
 * @param {data} data 
 */
async function removeService(args, data) {
    console.log();
    const { input, confirmed } = await prompt([
        {
            type: "list",
            name: "input",
            message: "Select a service",
            choices: serviceChoiceList(data.services).concat([divisionLine, exitOption])
        },
        {
            type: "confirm",
            name: "confirmed",
            message: "Removing this service will permanently delete the service and its' users, are you sure?",
            when: ans => !args.quick && ans.input !== "__exit"
        }
    ]);
    resetTimeout();
    if (input === "__exit")
        return;
    if (confirmed || args.quick) {
        delete data.services[input];
        saveFile(args, { data });
    }
}

// Service editing menu
const addUserOption = {
    name: "Add a user",
    short: "add user",
    value: "add"
};
const removeUserOption = {
    name: "Remove a user",
    short: "remove",
    value: "remove"
};
const editUserOption = {
    name: "Change a user's settings",
    short: "edit",
    value: "edit"
};
const removeUserBadOption = new inquirer.Separator(`${chalk.gray("Remove a user")} ${chalk.redBright("(No users registered)")}`);
const editUserBadOption = new inquirer.Separator(`${chalk.gray("Change a user's settings")} ${chalk.redBright("(No users registered)")}`);
/**
 * Service editing menu
 * @param {args} args 
 * @param {data} data 
 */
async function editService(args, data) {
    console.log();
    const { service } = await prompt([
        {
            type: "list",
            name: "service",
            message: "Select a service",
            choices: serviceChoiceList(data.services)
        }
    ]);
    resetTimeout();
    const { input } = await prompt([
        {
            type: "list",
            name: "input",
            message: `${chalk.reset.cyan("> " + service)} ${chalk.bold("What do you want to do?")}`,
            choices: _ => [addUserOption]
                .concat(data.services[service].length > 0 ? [removeUserOption, editUserOption] : [removeUserBadOption, editUserBadOption])
                .concat([divisionLine, exitOption])
        }
    ]);
    resetTimeout();
    switch (input) {
        case "add":
            await addUser(args, data, data.services[service]);
            break;
        case "remove":
            await removeUser(args, data, data.services[service]);
            break;
        case "edit":
            await editUser(args, data, data.services[service], service);
            break;
        case "__exit":
            return;
    }
}

/**
 * Menu for adding a user to a service
 * @param {args} args 
 * @param {data} data 
 * @param {{}[]} service 
 */
async function addUser(args, data, service) {
    let keepGoing = true;
    while (keepGoing) {
        console.log();
        const { name, salt, length, note, repeat } = await prompt([
            {
                type: "input",
                name: "name",
                message: "Username or Email",
                validate: inp => service.find(v => v.name === (inp || "null")) ? "That username is already registered for this service" : true
            },
            {
                type: "input",
                name: "salt",
                message: "Salt",
                suffix: " (optional)",
            },
            {
                type: "input",
                name: "length",
                message: "Length",
                default: defaultLength,
                validate: inp => validateLength(Number(inp))
            },
            {
                type: "input",
                name: "note",
                message: "Note",
                suffix: " (optional)",
            },
            {
                type: "list",
                name: "repeat",
                message: "Do you want to add another user to this service",
                choices: [{ name: "Yes", value: true }, { name: "No", value: false }]
            }
        ]);
        resetTimeout();
        service.push({
            name: name || "null",
            salt,
            length: Number(length),
            note
        });
        saveFile(args, { data });
        keepGoing = repeat;
    }
}

/**
 * Menu for deleting a user from a service
 * @param {args} args 
 * @param {data} data 
 * @param {{}[]} service 
 */
async function removeUser(args, data, service) {
    console.log();
    const { input, confirmed } = await prompt([
        {
            type: "list",
            name: "input",
            message: "Select a user",
            choices: userChoiceList(service, true).concat([divisionLine, exitOption])
        },
        {
            type: "confirm",
            name: "confirmed",
            message: "Removing this user will permanently delete it and its' configuration, are you sure?",
            when: ans => !args.quick && ans.input !== "__exit"
        }
    ]);
    resetTimeout();
    if (input === "__exit")
        return;
    if (confirmed || args.quick) {
        service.splice(input, 1);
        saveFile(args, { data });
    }
}

/**
 * Menu for editing a users properties
 * @param {args} args 
 * @param {data} data 
 * @param {{}[]} service
 * @param {string} serviceName 
 */
async function editUser(args, data, service, serviceName) {
    console.log();
    const choices = userChoiceList(service, true);
    const { input } = await prompt([
        {
            type: "list",
            name: "input",
            message: "Select a user",
            choices: choices
        }
    ], choices.length === 1 ? { input: 0 } : null);
    console.log();
    console.log(infoPrefix, "Username:", chalk.cyan(service[input].name));
    console.log(infoPrefix, "Salt:", chalk.cyan(service[input].salt));
    console.log(infoPrefix, "Length:", chalk.cyan(service[input].length));
    console.log(infoPrefix, "note:", chalk.cyan(service[input].note));
    console.log();
    resetTimeout();
    // Allow editing multiple properties until the user is done
    while (true) {
        const { action } = await prompt([{
            type: "list",
            name: "action",
            message: `${chalk.reset.cyan("> " + serviceName + " > " + service[input].name)} ${chalk.bold("What do you want to do?")}`,
            choices: [
                {
                    name: "Change username",
                    short: "username",
                    value: "name"
                },
                {
                    name: "Change salt",
                    short: "salt",
                    value: "salt"
                },
                {
                    name: "Change length",
                    short: "length",
                    value: "length"
                },
                {
                    name: "Change note",
                    short: "note",
                    value: "note"
                },
                divisionLine,
                exitOption
            ]
        }]);
        resetTimeout();
        const question = {
            type: "input",
            name: `new${action}`,
            message: `Enter the new ${action}`
        }
        switch (action) {
            case "name":
                question.validate = inp => service.find(v => v.name === (inp || "null")) && (inp || "null") !== service[input].name ? "That username is already registered for this service" : true;
                const { newname } = await prompt([question]);
                resetTimeout();
                service[input].name = newname || "null";
                saveFile(args, { data });
                break;
            case "salt":
                const { newsalt } = await prompt([question]);
                resetTimeout();
                service[input].salt = newsalt;
                saveFile(args, { data });
                break;
            case "length":
                question.validate = inp => validateLength(Number(inp));
                const { newlength } = await prompt([question]);
                resetTimeout();
                service[input].length = Number(newlength);
                saveFile(args, { data });
                break;
            case "note":
                const { newnote } = await prompt([question]);
                resetTimeout();
                service[input].note = newnote;
                saveFile(args, { data });
                break;
            case "__exit":
                return;
        }
        resetTimeout();
    }
}

/**
 * Menu for changing the master password
 * @param {args} args 
 * @param {data} data 
 */
async function resetMaster(args, data) {
    const { confirmed, password } = await prompt([
        {
            type: "confirm",
            name: "confirmed",
            message: "Changing your master password will change the passwords of all registered accounts. Are you sure?",
            when: !args.quick
        },
        {
            type: args.passwordVisibility === "CLEAR" ? "input" : "password",
            name: "password",
            message: "New Master Password",
            mask: args.passwordVisibility === "MASKED" ? "*" : null,
            when: ans => ans.confirmed
        }
    ]);
    resetTimeout();
    if (confirmed || args.quick) {
        console.log(infoPrefix, "Generating key and checksum for the new password");
        await initEncryptionKey(password, true);
        const checksum = await hash(password, MASTER_OPTIONS);
        resetTimeout();
        saveFile(args, { checksum, data });
        console.log(infoPrefix, "New master password registered");
    }
}

/**
 * Export the encrypted data in an unencrypted format
 * @param {args} args 
 * @param {data} data 
 */
async function exportData(args, data) {
    const cwd = process.cwd();
    const path = getSafePathForNewJsonFile(cwd + "/export.json").split("\\").join("/");
    const string = JSON.stringify(data, null, 2);
    console.log();
    console.log(string);
    console.log();
    const { confirmed } = await prompt([{
        type: "confirm",
        name: "confirmed",
        message: `This will dump the above data into ${path}. Are you sure?`
    }]);
    if (confirmed) {
        writeFileSync(path, string);
    }
}

// Parse services into list choices
const serviceChoiceList = services => Object.getOwnPropertyNames(services).map(v => ({ name: `${v.padEnd(Math.max(...Object.getOwnPropertyNames(services).map(v => v.length)))} (${services[v].length === 0 ? "1 default user" : services[v].length === 1 ? "1 user" : services[v].length + " users"})`, short: v, value: v }));

// Parse users into list choices
const userChoiceList = (service, useIndexes) => service.map((v, i) => ({
    name: v.note ? `${v.name.padEnd(Math.max(...service.map(v => v.name.length)))} ${chalk.rgb(...grayBright)(v.note)}` : v.name,
    short: v.name,
    value: useIndexes ? i : [v]
}));

export {
    noDataRetrievalDialogue,
    getMasterPassword,
    retrievePasswords,
    mainMenu
};
