import arg from "arg";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const uuid = require("uuid");

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
        "-ma": "--major",
        "-mi": "--minor",
        "-p": "--patch",
        "-u": "--user",
        "-e": "--expire",
        "-pu": "--public",
        "-pr": "--private",
        "-l": "--license",
        "-o": "--output",
        "-pk": "--private-key",
        "-pubk": "--public-key",
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
        privateKey: args["--private-key"] || null,
        publicKey: args["--public-key"] || null,
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

    const { user } = options;

    if (!user) {
        throw new Error('Please pass an email of the user');
    }

    // Define user license options/values
    const userData = {
        id: uuid.v4(),
        major: options.major,
        minor: options.minor,
        patch: options.patch,
        user,
        created: Date.now(),
        expire: options.expire,
    };

    const { privateKeyPath, publicKeyPath } = options

    let privateKey, publicKey;

    if (privateKeyPath && publicKeyPath) {
        privateKey = fs.readFileSync(privateKeyPath);
        publicKey = fs.readFileSync(publicKeyPath);
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

    console.log(`Saving public key file to '${publicKeyFilePath}'.`);
    fs.writeFileSync(publicKeyFilePath, publicKey);

    console.log(`Saving private key file to '${privateKeyFilePath}'.`);
    fs.writeFileSync(privateKeyFilePath, privateKey);

    console.log(`Saving license file to '${licenseFilePath}'.`);
    fs.writeFileSync(licenseFilePath, encrypted);
}
