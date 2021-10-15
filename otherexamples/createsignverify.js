window.crypto.subtle.generateKey({
    name: "ECDSA",
    namedCurve: "P-384",
},
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //can be any combination of "sign" and "verify"
)
    .then(function (key) {

        var publicKey = key.publicKey;
        var privateKey = key.privateKey;
        // For Demo Purpos Only Exported in JWK format
        window.crypto.subtle.exportKey("jwk", key.publicKey).then(
            function (keydata) {
                publicKeyhold = keydata;
                publicKeyJson = JSON.stringify(publicKeyhold);
                document.getElementById("ecdsapublic").value = publicKeyJson;
            }
        );

        window.crypto.subtle.exportKey("jwk", key.privateKey).then(
            function (keydata) {
                privateKeyhold = keydata;
                privateKeyJson = JSON.stringify(privateKeyhold);
                document.getElementById("ecdsaprivate").value = privateKeyJson;
            }
        );

        window.crypto.subtle.sign({
            name: "ECDSA",
            hash: {
                name: "SHA-256"
            }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
            privateKey, //from generateKey or importKey above
            asciiToUint8Array(plainText) //ArrayBuffer of data you want to sign
        )
            .then(function (signature) {
                //returns an ArrayBuffer containing the signature
                document.getElementById("cipherText").value = bytesToHexString(signature);
            })
            .catch(function (err) {
                console.error(err);
            });


    })
    .catch(function (err) {
        console.error(err);
    });

window.crypto.subtle.verify({
    name: "ECDSA",
    hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
},
    publicKey, //from generateKey or importKey above
    hexStringToUint8Array(cipherText), //ArrayBuffer of the data
    asciiToUint8Array(plainText)
)
    .then(function (decrypted) {
        alert("Verified   " + decrypted);
    })
    .catch(function (err) {
        console.error(err);
    });