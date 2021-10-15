// @ts-nocheck

function initTPM() {
    window.crypto.subtle.tpmInit();
}


function tpmCreatePrimary() {
    window.crypto.subtle.tpmCreatePrimary();
}

function tpmCreate() {
    window.crypto.subtle.tpmCreate();
}

function tpmEncrypt() {
    window.crypto.subtle.tpmEncrypt();
}

function tpmDecrypt() {
    window.crypto.subtle.tpmDecrypt();
}

async function tpmGetRandom() {
    const tpmSaltArrayBuffer = await window.crypto.subtle.tpmGetRandom();
    const salt = new Uint8Array(tpmSaltArrayBuffer);
    const tpmIVArrayBuffer = await window.crypto.subtle.tpmGetRandom();
    const iv = new Uint8Array(tpmIVArrayBuffer);
    console.log(salt, iv);
}

function tpmFlushContext() {
    window.crypto.subtle.tpmFlushContext();
    initTPM()
    // tpmGetRandom()
    tpmCreatePrimary()
}

const buff_to_base64 = (buff) => btoa(String.fromCharCode.apply(null, buff));

const base64_to_buf = (b64) =>
    Uint8Array.from(atob(b64), (c) => c.charCodeAt(null));

const enc = new TextEncoder();
const dec = new TextDecoder();

async function encrypt() {
    const data = window.document.getElementById("data").value;
    let encryptedDataOut = window.document.getElementById("encryptedData");
    const password = window.prompt("Password");
    const encryptedData = await encryptData(data, password);
    encryptedDataOut.value = encryptedData;
}

async function digestMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hash = await crypto.subtle.digestTest('SHA-256', data);
    return hash;
}

async function decrypt() {
    const password = window.prompt("Password");
    const encryptedData = window.document.getElementById("encryptedData").value;
    let decryptedDataOut = window.document.getElementById("decrypted");
    const decryptedData = await decryptData(encryptedData, password);
    decryptedDataOut.value = decryptedData || "decryption failed!";
}

console.log("generating key in jss");
// initTPM()
// // tpmGetRandom()
// tpmCreatePrimary()
// tpmCreate()
// let key = window.crypto.subtle.generateKey(
//         {
//         name: "AES-GCM",
//         length: 128
//         },
//         true,
//         ["encrypt", "decrypt"]
//     );


const getPasswordKey = (password) => {
    return window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, [
        "deriveKey",
    ])
};

const deriveKey = (passwordKey, salt, keyUsage) =>
    window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256",
        },
        passwordKey,
        { name: "AES-GCM", length: 128 },
        false,
        keyUsage
    );

async function encryptData(secretData, password) {
    try {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        // const tpmSaltArrayBuffer = await window.crypto.subtle.tpmGetRandom();   // fixed on 16 bytes
        // const salt = new Uint8Array(tpmSaltArrayBuffer);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        // const tpmIVArrayBuffer = await window.crypto.subtle.tpmGetRandom();
        // const iv = new Uint8Array(tpmIVArrayBuffer);
        //console.log(salt);
        // digestTest
        // const text = 'An obscure body in the S-K System, your majesty. The inhabitants refer to it as the planet Earth.';
        // digestMessage(text)
        // .then(digestBuffer => console.log(digestBuffer));
        //window.crypto.subtle.tpmInitCreateSignVerify();
        console.log("getPasswordKey")
        const passwordKey = await getPasswordKey(password);
        console.log("deriveKey")
        const aesKey = await deriveKey(passwordKey, salt, ["encrypt"]);
        console.log(aesKey);
        // tpmCreate();
        // tpmEncrypt();
        console.log(secretData)
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            aesKey,
            enc.encode(secretData)
        );
        console.log(encryptedContent);
        const encryptedContentArr = new Uint8Array(encryptedContent);
        console.log(encryptedContentArr);
        let buff = new Uint8Array(
            salt.byteLength + iv.byteLength + encryptedContentArr.byteLength
        );
        buff.set(salt, 0);
        buff.set(iv, salt.byteLength);
        buff.set(encryptedContentArr, salt.byteLength + iv.byteLength);
        const base64Buff = buff_to_base64(buff);
        console.log("encrypt")
        return base64Buff;
    } catch (e) {
        console.log(`Error - ${e}`);
        return "";
    }
}

async function decryptData(encryptedData, password) {
    try {
        const encryptedDataBuff = base64_to_buf(encryptedData);
        const salt = encryptedDataBuff.slice(0, 16);
        const iv = encryptedDataBuff.slice(16, 16 + 12);
        const data = encryptedDataBuff.slice(16 + 12);
        const passwordKey = await getPasswordKey(password);
        const aesKey = await deriveKey(passwordKey, salt, ["decrypt"]);
        // tpmDecrypt();
        const decryptedContent = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            aesKey,
            data
        );
        console.log("decrypt")
        console.log(decryptedContent);
        return dec.decode(decryptedContent);
    } catch (e) {
        console.log(`Error - ${e}`);
        return "";
    }
}
