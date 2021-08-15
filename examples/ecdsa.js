import { ECDH } from "../ECDH.js";
import { SHA256 } from "https://taisukef.github.io/sha256-es/SHA256.js";

// Pick some curve
//const type = "secp256k1";
const type = "secp256r1";
const curve = ECDH.getCurve(type);
		
// Choose algorithm to the hash function
const algorithm = "sha256";

// Generate random keys for Alice
const aliceKeys = ECDH.generateKeys(curve);

// Hash something so we can have a digest to sign
//const message = new Buffer('Hello World');
const message = new TextEncoder().encode('Hello World');
//const hash = crypto.createHash(algorithm).update(message).digest();
const hash = SHA256.digest(message);
console.log('Hashed message to sign:', hash); // hash.toString('hex'));
console.log('Hashed message to sign:', hash.toString('hex'));

// Sign it with Alice's key
const signature = aliceKeys.privateKey.sign(hash, algorithm);
console.log('Signature:', signature); // .toString('hex'));
console.log('Signature:', signature.toString('hex'));

// Verify it with Alice public key
const valid = aliceKeys.publicKey.verifySignature(hash, signature);
console.log('Signature is', valid ? 'valid :)' : 'invalid!!');
