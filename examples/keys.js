import { ECDH } from "../ECDH.js";

//console.log(crypto)
//console.log(await crypto.randomBytes(10));

const type = "secp256r1";
// Pick some curve
const curve = ECDH.getCurve(type);

// Generate random key
const privateKey = ECDH.PrivateKey.generate(curve);
// generate public key from private key
const publicKey = privateKey.derivePublicKey();

// Or you may get the key from a buffer:
// privateKey = ecdh.PrivateKey.fromBuffer(curve, buf2);

console.log('private key length:', privateKey.buffer.length);
console.log('private key:', privateKey.buffer.toString('hex'));
console.log('public key length:', publicKey.buffer.length);
console.log('public key:', publicKey.buffer.toString('hex'));
