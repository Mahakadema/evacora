
import { readFileSync } from "fs";
import arg2 from "argon2";
const { argon2id, hash, verify } = arg2;
import clip from "clipboardy";
const write = clip.write;

/**
 * @constant dataLocation location of your data file, if existing
 */
const dataLocation = "./.json";

const MEMORY_COST = 262144;
const TIME_COST = 20;
const PARALLELISM = 4;

const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const charset = "!#$%()*,-./0123456789:@ABCDEFGHIJKLMNOPQR^_`abcdefghijklmnopqr|~";

async function main() {
    const name = process.argv.includes("-n", 2) ? process.argv[process.argv.indexOf("-n", 2) + 1] : null;
    const pw = process.argv.includes("-p", 2) ? process.argv[process.argv.indexOf("-p", 2) + 1] : null;
    const salt = process.argv.includes("-s", 2) ? Number(process.argv[process.argv.indexOf("-s", 2) + 1]) : "";
    const user = process.argv.includes("-u", 2) ? process.argv[process.argv.indexOf("-u", 2) + 1] : null;
    const length = process.argv.includes("-l", 2) ? Number(process.argv[process.argv.indexOf("-l", 2) + 1]) : 30;
    const useClipboard = process.argv.includes("-c", 2);

    try {
        await get(name, pw, salt, user ? [user] : [null], length, useClipboard ? "CLIPBOARD" : "STDOUT");
    } catch (e) {
        console.log("Error:", e.message);
        process.exit(1);
    }
}

async function get(name, pw, salt, users, length, outputMethod) {
    // check reqs
    if (length > 60 || length < 16)
        throw new Error("Length has to be between 16 and 60 inclusive");
    if (!name)
        throw new Error("Name required!");
    if (!pw)
        throw new Error("Password required!");

    // get data if available
    let checksum = "null";
    try {
        const data = JSON.parse(readFileSync(dataLocation, "utf-8"));
        checksum = data.checksum ?? "null";
        if (users[0]) {
            // find full name of provided alias
            let found = false;
            for (const user of data[name]) {
                if (user.names.map(v => v.toLowerCase()).includes(users[0].toLowerCase())) {
                    users[0] = { u: user.names[0], s: user.salt, l: user.length, n: user.note };
                    found = true;
                    break;
                }
            }
            if (!found)
                throw new Error();
        } else {
            // fill with all usernames associated with service name
            users = [];
            for (const user of data[name]) {
                users.push({ u: user.names[0], s: user.salt, l: user.length, n: user.note });
            }
            if (users.length === 0) {
                users.push("null");
                throw new Error();
            }
        }
    } catch (e) {
        users[0] = { u: users[0] ?? "null", s: salt, l: length, n: "" };
        console.log(`No data for ${users[0].u}@${name} found! Resorting to user="${users[0].u}" salt="${users[0].s}" length=${users[0].l}`);
    }

    // check for correct pw
    if (checksum === "null") {
        const pwHash = await hash(pw, {
            type: argon2id,
            hashLength: 30,
            memoryCost: MEMORY_COST,
            timeCost: TIME_COST,
            parallelism: PARALLELISM
        });
        console.log(`Password checksum:\n"${pwHash}"\nSet 'checksum' in your local file to this value to enable password checking.`);
    } else {
        if (!await verify(checksum, pw))
            throw new Error(`Password incorrect!`);
        console.log("Password accepted!");
    }

    // generate passwords
    const final = [];
    for (const u of users) {
        final.push((await hash(pw, {
            type: argon2id,
            salt: Buffer.from(`ASk[Jw,%7/M"~&p9!H|Lfl3FUw{3l;P!${u.s}#${u.u}@${name}`),
            hashLength: u.l,
            memoryCost: MEMORY_COST,
            timeCost: TIME_COST,
            parallelism: PARALLELISM
        })).split("$").at(-1).split("").slice(0, length));
    }

    // log
    for (const str of final) {
        for (let i = 0; i < str.length; i++) {
            str[i] = charset[base64.indexOf(str[i])];
        }
    }
    switch (outputMethod) {
        case "CLIPBOARD":
            write(final.map(v => v.join("")).join("\n"));
            console.log("Copied to clipboard!");
            setTimeout(() => { console.log("Deleted from clipboard!"); write("null"); }, 15000);
            break;
        case "STDOUT":
            console.log(`\n${name}${users.reduce((p, c, i) => p + `\n  ${(c.s + "# " + c.u).padEnd(40)} ${final[i].join("")}    ${c.n}`, "")}`);
            break;
    }
}

main();
