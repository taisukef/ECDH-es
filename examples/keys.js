import { ECDH } from "../ECDH.js";

//enable debugging
ECDH.zeroSetDebug(true);

// Pick some curve
const type = "secp256r1";
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

privateKey.zero();
publicKey.zero();

//debug ECDH -- should not throw!
ECDH.zeroDebug();
