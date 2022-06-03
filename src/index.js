import arg from "arg";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const uuid = require("uuid");
const add = require("date-fns/add");

function parseArgumentsIntoOptions(rawArgs) {
    const args = arg({
        "--major": String,
        "--minor": String,
        "--patch": String,
        "--user": String,
        "--expire": String,
        "--public": String,
        "--private": String,
        "--license": String,
        "--output": String,
        "--private-key": String,
        "--public-key": String,
        "--valid-to": String,
        "-ma": "--major",
        "-mi": "--minor",
        "-pa": "--patch",
        "-u": "--user",
        "-e": "--expire",
        "-pu": "--public",
        "-pr": "--private",
        "-l": "--license",
        "-o": "--output",
        "-pk": "--private-key",
        "-pubk": "--public-key",
        "-vt": "--valid-to",
    }, {
        permissive: false,
        argv: rawArgs.slice(2),
        stopAtPositional: false
    });
    return {
        major: args["--major"] || "*",
        minor: args["--minor"] || "*",
        patch: args["--patch"] || "*",
        user: args["--user"] || "",
        expire: args["--expire"] || "",
        public: args["--public"] || "public.key",
        private: args["--private"] || "private.key",
        license: args["--license"] || "license.data",
        output: args["--output"] || process.cwd(),
        privateKeyPath: args["--private-key"] || null,
        publicKeyPath: args["--public-key"] || null,
        validTo: args["--valid-to"] || null,
    };
}

const cryptoKeyPairOptions = {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: "spki",
        format: "pem"
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem"
    }
};

export function cli(args) {
    const options = parseArgumentsIntoOptions(args);

    const { user, validTo, expire } = options;

    if (!user) {
        throw new Error('Please pass an email of the user');
    }

    let validToDate = null

    const now = new Date()

    if (validTo) {
        const validToYearsPattern = validTo.match(/^years-(\d*)$/i)
        const validToMonthsPattern = validTo.match(/^months-(\d*)$/i)
        const validToDaysPattern = validTo.match(/^days-(\d*)$/i)
        const validToHoursPattern = validTo.match(/^hours-(\d*)$/i)
        const validToMinutesPattern = validTo.match(/^minutes-(\d*)$/i)
        const validToSecondsPattern = validTo.match(/^seconds-(\d*)$/i)

        if (validToYearsPattern && validToYearsPattern[1]) {
            validToDate = add(now, {
                years: validToYearsPattern[1],
            })
        } else if (validToMonthsPattern && validToMonthsPattern[1]) {
            validToDate = add(now, {
                months: validToMonthsPattern[1],
            })
        } else if (validToDaysPattern && validToDaysPattern[1]) {
            validToDate = add(now, {
                days: validToDaysPattern[1],
            })
        } else if (validToHoursPattern && validToHoursPattern[1]) {
            validToDate = add(now, {
                hours: validToHoursPattern[1],
            })
        } else if (validToMinutesPattern && validToMinutesPattern[1]) {
            validToDate = add(now, {
                minutes: validToMinutesPattern[1],
            })
        } else if (validToSecondsPattern && validToSecondsPattern[1]) {
            validToDate = add(now, {
                seconds: validToSecondsPattern[1],
            })
        }
    }

    // Define user license options/values
    const userData = {
        id: uuid.v4(),
        major: options.major,
        minor: options.minor,
        patch: options.patch,
        user,
        created: now,
        validTo: validToDate,
        expire: expire ? new Date(expire) : null,
    };

    const { privateKeyPath, publicKeyPath } = options

    let privateKey, publicKey, usingExistingKeyPair = false;

    if (privateKeyPath && publicKeyPath) {
        privateKey = fs.readFileSync(path.resolve(privateKeyPath));
        publicKey = fs.readFileSync(path.resolve(publicKeyPath));
        usingExistingKeyPair = true
    } else {
        // Generate a public/private keypair
        const certPair = crypto.generateKeyPairSync("rsa", cryptoKeyPairOptions);
        publicKey = certPair.publicKey;
        privateKey = certPair.privateKey;
    }

    // Sign user data with the private key
    const encrypted = crypto.privateEncrypt(privateKey, Buffer.from(JSON.stringify(userData)));

    // Save license data, along with public/private keys
    const publicKeyFilePath = path.join(options.output, options.public);
    const privateKeyFilePath = path.join(options.output, options.private);
    const licenseFilePath = path.join(options.output, options.license);

    console.log(`${usingExistingKeyPair ? 'Using' : 'Saving'} public key file at '${publicKeyFilePath}'.`);
    fs.writeFileSync(publicKeyFilePath, publicKey);

    console.log(`${usingExistingKeyPair ? 'Using' : 'Saving'} private key file at '${privateKeyFilePath}'.`);
    fs.writeFileSync(privateKeyFilePath, privateKey);

    console.log(`Saving license file at '${licenseFilePath}'.`);
    fs.writeFileSync(licenseFilePath, encrypted);
}
