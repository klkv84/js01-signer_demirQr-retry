var crypto = require("crypto"),
    fs = require("fs");

var signer, sign, verifier, privateKey, publicKey, result;

privateKey = fs.readFileSync("private.pem", "utf8");
publicKey = fs.readFileSync("public.pem", "utf8");

signer = crypto.createSign("RSA-SHA256");
// signer.update("https://apigatewaytest.demirbank.kg/accountapi/accounts/kulikov/qr/generate/1181000500174594/1/KGS");
signer.update("https://apigatewaytest.demirbank.kg/psp/api/v1/kulikov/extensions/status/0b34870f5aea45cba9e80d4c8f85049a");



sign = signer.sign({key:privateKey,padding:crypto.constants. RSA_PKCS1_PADDING}, "base64");
console.log(sign); 

// verifier = crypto.createVerify("RSA-SHA256");
// verifier.update("https://apigatewaytest.demirbank.kg/accountapi/accounts/kulikov/qr/generate/1181000500174594/1/KGS"); 
// result = verifier.verify(({key:publicKey,padding:crypto.constants. RSA_PKCS1_PADDING}, sign, "base64"));
// console.log(result);//true if ok

// Проверка подписи
verifier = crypto.createVerify("RSA-SHA256");
// verifier.update("https://apigatewaytest.demirbank.kg/accountapi/accounts/kulikov/qr/generate/1181000500174594/1/KGS");
verifier.update("https://apigatewaytest.demirbank.kg/psp/api/v1/kulikov/extensions/status/0b34870f5aea45cba9e80d4c8f85049a");

// Здесь аргументы нужно передать отдельно
result = verifier.verify({key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(sign, 'base64'));
console.log("Verified:", result);  // Должен вывести true или false