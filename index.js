
import { readFileSync } from "fs";
import arg2 from "argon2";
const { argon2id, hash, verify } = arg2;
import clip from "clipboardy";
const write = clip.write;
import arg from "arg";
import inquirer from "inquirer";
import chalk from "chalk";


const MEMORY_COST = 262144;
const TIME_COST = 20;
const PARALLELISM = 4;

const defaultFile = "./.json";
const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const defaultCharset = "!#$%()*,-./0123456789:@ABCDEFGHIJKLMNOPQR^_`abcdefghijklmnopqr|~";
const defaultLength = 30;
const strongPasswordBarrier = 90;

const errorPrefix = chalk.red("[") + chalk.redBright("ERROR") + chalk.red("]");
const warnPrefix = chalk.yellow("[") + chalk.yellowBright("WARN") + chalk.yellow("]");
const infoPrefix = chalk.rgb(11, 142, 130)("[") + chalk.rgb(38, 226, 208)("INFO") + chalk.rgb(11, 142, 130)("]");
const debugPrefix = chalk.white("[") + chalk.whiteBright("DEBUG") + chalk.white("]");
const grayBright = [164, 164, 164];


async function main() {
    // parse argv
    let args;
    try {
        args = arg(
            {
                // args
                "--help": Boolean,
                "--file": String,
                "--charset": String,
                "--verbose": Boolean,
                "--copy": Boolean,

                // alias
                "-h": "--help",
                "-f": "--file",
                "-m": "--charset",
                "-v": "--verbose",
                "-c": "--copy"
            },
            {
                permissive: false,
                argv: process.argv.slice(2),
            }
        );

        if (!args["--file"])
            args["--file"] = defaultFile;

        if (!/^(?:\w\:)?(?:[^\\\/]*\\\/)*.*\.json$/.test(args["--file"]))
            throw new Error("The --file option has to be a path pointing to a JSON file");

        if (!args["--charset"])
            args["--charset"] = defaultCharset;

        args["--charset"] = args["--charset"].split("").sort().join("");

        if (args["--charset"].length > 64)
            throw new Error("The charset cannot exceed 64 characters in size");

        args["--copy"] ??= false;
        args["--verbose"] ??= false;
        args["--help"] ??= false;
    } catch (e) {
        if (process.argv.includes("-v") || process.argv.includes("--verbose")) {
            console.log(errorPrefix, "Couldn't parse arguments:", e);
        } else {
            console.log(errorPrefix, "Couldn't parse arguments:", e.message);
        }
        process.exit(1);
    }

    // help
    if (args["--help"]) {
        helpMessage();
        process.exit(0);
    }

    // get data if available and sanity check
    let checksum = "null";
    let data;
    try {
        data = JSON.parse(readFileSync(args["--file"], "utf-8"));;
        checksum = data.checksum ?? "null";
        if (typeof data.checksum !== "string")
            throw new TypeError('"checksum" needs to be a string');
        if (typeof data.services !== "object")
            throw new TypeError('"services" needs to be an object');
    } catch (e) {
        if (args["--verbose"]) {
            console.log(warnPrefix, "Failed to load file! Continuing without data\n" + warnPrefix, e);
        } else {
            console.log(warnPrefix, `Failed to load file! Continuing without data\n${warnPrefix} ${e}`);
        }
    }

    const prompt = inquirer.createPromptModule();

    // main loop
    try {
        let password;
        while (true) {
            // call password generator
            password = await get({
                copy: args["--copy"],
                file: args["--file"],
                charset: args["--charset"],
                verbose: args["--verbose"],
                password: password,
                checksum: checksum
            }, data);

            // set up race between confirmation and timeout
            console.log(infoPrefix, "Terminating in 10 seconds if no interaction is received");
            await Promise.race([
                new Promise(resolve => setTimeout(resolve, 10000)),
                prompt([{
                    type: "confirm",
                    name: "continue",
                    message: "Do you want to generate more passwords?"
                }])
            ]).then(res => res?.continue ? null : process.exit(0));
        }
    } catch (e) {
        if (args["--verbose"]) {
            console.log(errorPrefix, "Error in main loop:", e);
        } else {
            console.log(errorPrefix, "Error in main loop:", e.message);
        }
        process.exit(1);
    }
}

/**
 * @param {{}} args the command line args
 * @param {{}} data the JSON data from the data file
 * @returns {string} The master password
 */
async function get(args, data) {
    // prepare questions
    const lengthValidator = input => input > 3 && input < 4294967296 && Number.isInteger(input) ? true : "Length has to be an integer between 4 and 4294967295";
    const questions = [
        {
            type: null,
            name: "service",
            message: "Service Name"
        },
        {
            type: null,
            name: "__user",
            message: "Username"
        },
        {
            type: "input",
            name: "__salt",
            message: "Salt (optional)",
            when: ans => ans.users.some(v => v.s === null),
            filter: (input, ans) => {
                ans.users.forEach((v) => {
                    if (v.s === null)
                        v.s = input;
                });
                return input;
            }
        },
        {
            type: "number",
            name: "__length",
            message: "Length",
            default: defaultLength,
            when: ans => ans.users.some(v => v.l === null),
            validate: lengthValidator,
            filter: (input, ans) => {
                if (lengthValidator(input) === true)
                    ans.users.forEach((v) => {
                        if (v.l === null)
                            v.l = input;
                    });
                return input;
            }
        },
        {
            type: "password",
            name: "password",
            message: "Master Password",
            mask: "*",
            validate: async input => args.checksum !== "null" ? (await verify(args.checksum, input)) ? true : "Password Incorrect" : true
        }
    ];

    if (data) {
        questions[0].type = "list";
        questions[1].type = "list";
        questions[0].choices = [];
        for (const service of Object.keys(data.services)) {
            if (data.services.hasOwnProperty(service)) {
                questions[0].choices.push({
                    name: service,
                    value: service
                });
            }
        }
        questions[1].choices = (ans) =>
            [{
                name: "All",
                value: data.services[ans.service]
                    .map(v => typeof v === "string" ? { u: v, s: null, l: null, n: "" } : { u: v.name, s: v.salt ?? "", l: v.length >= 4 ? v.length : defaultLength, n: v.note ?? "" })
            }]
                .concat(data.services[ans.service].map(v => ({
                    name: typeof v === "string" ? v : v.name,
                    value: [typeof v === "string" ? { u: v, s: null, l: null, n: "" } : { u: v.name, s: v.salt ?? "", l: v.length >= 4 ? v.length : defaultLength, n: v.note ?? "" }]
                })));
        questions[1].filter = (input, ans) => {
            ans.users = input;
            return input;
        }
    } else {
        questions[0].type = "input";
        questions[1].type = "input";
        questions[0].validate = input => input?.length > 0 ? true : "Service Name cannot be empty";
        questions[1].filter = (input, ans) => {
            ans.users = [{ u: input || "null", s: null, l: null, n: "" }];
            return input || "null";
        };
    }

    // ask questions
    const prompt = inquirer.createPromptModule();
    args = await prompt(questions, args);
    const outputMethod = args.copy ? "CLIPBOARD" : "STDOUT";

    if (args.verbose) {
        console.log(`\n${debugPrefix} Options:\n` +
            `${debugPrefix} file: ${chalk.greenBright(args.file)}\n` +
            `${debugPrefix} charset: ${chalk.greenBright(args.charset)}\n` +
            `${debugPrefix} service name: ${chalk.greenBright(args.service)}\n` +
            `${debugPrefix} password: ${chalk.greenBright("*".repeat(args.password.length))}\n` +
            `${debugPrefix} users:${args.users.reduce((p, c) => p + `\n${debugPrefix}   ${chalk.greenBright(c.s.padStart(args.users.reduce((p, c) => Math.max(p, c.s.length), 0)))} # ${chalk.greenBright(c.u)} {${chalk.greenBright(c.l)}}`, "")}\n` +
            `${debugPrefix} output method: ${chalk.greenBright(outputMethod)}`);
    }

    // check password strength
    const entropy = Math.log2(args.charset.length) * args.users.reduce((p, c) => Math.min(p, c.l), Number.MAX_SAFE_INTEGER);
    if (entropy < strongPasswordBarrier)
        console.log(`${warnPrefix} One of the passwords you are generating only has ${entropy} bits of entropy.\n${warnPrefix} Generating a longer password or using a larger charset is recommended.`);

    // check for correct pw
    if (args.checksum === "null") {
        const pwHash = await hash(args.password, {
            type: argon2id,
            hashLength: 32,
            memoryCost: MEMORY_COST,
            timeCost: TIME_COST,
            parallelism: PARALLELISM
        });
        console.log(`${infoPrefix} Password checksum:\n${infoPrefix} "${pwHash}"\n${infoPrefix} Set 'checksum' in your local file to this value to enable password checking.`);
    }

    // generate passwords
    const final = [];
    for (const u of args.users) {
        final.push((await hash(args.password, {
            type: argon2id,
            salt: Buffer.from(`ASk[Jw,%7/M"~&p9!H|Lfl3FUw{3l;P!${u.s}#${u.u}@${args.service}`),
            hashLength: u.l,
            memoryCost: MEMORY_COST,
            timeCost: TIME_COST,
            parallelism: PARALLELISM
        })).split("$").at(-1).split("").slice(0, u.l));
    }

    // out
    for (const str of final) {
        for (let i = 0; i < str.length; i++) {
            str[i] = args.charset[base64.indexOf(str[i]) % args.charset.length];
        }
    }

    switch (outputMethod) {
        case "CLIPBOARD":
            write(final.map(v => v.join("")).join("\n"));
            console.log(infoPrefix, "Copied to clipboard!");

            await new Promise(resolve => setTimeout(resolve, 15000));

            write("null");
            console.log(infoPrefix, "Deleted from clipboard!");
            break;
        case "STDOUT":
            console.log(`\n${infoPrefix} [${chalk.cyan(args.service)}]${args.users.reduce((p, c, i) => p + `\n${infoPrefix} ${chalk.rgb(...grayBright)(c.s.padStart(args.users.reduce((p, c) => Math.max(p, c.s.length), 0)))} ${chalk.gray("#")} ${chalk.white(c.u.padEnd(30))} ${chalk.redBright(final[i].join(""))}    ${chalk.rgb(...grayBright)(c.n)}`, "")}`);
            break;
    }
    console.log();

    return args.password;
}

function helpMessage() {
    const packageJson = JSON.parse(readFileSync("./package.json", "utf-8"));
    console.log(`${infoPrefix} evacora v${packageJson.version}\n` +
        `${infoPrefix}\n` +
        `${infoPrefix} A stateless password manager\n` +
        `${infoPrefix}\n` +
        `${infoPrefix} Available options:\n` +
        `${infoPrefix} --help, -h               display this list\n` +
        `${infoPrefix} --file, -f <path>        specify a file containing registered accounts\n` +
        `${infoPrefix} --charset, -m <charset>  specify up to 64 characters to be used in the passwords\n` +
        `${infoPrefix} --verbose, -v            log verbosely\n` +
        `${infoPrefix} --copy, -c               copy the passwords into the clipboard instead of using STDOUT`);
}

main();
