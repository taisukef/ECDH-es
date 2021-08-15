//var crypto = require('crypto');
//import crypto from "https://deno.land/std@0.104.0/node/crypto.ts";
import { SHA256 } from "https://taisukef.github.io/sha256-es/SHA256.js";
import { ecdh } from "../index.js";
import { Buffer } from "https://deno.land/std@0.104.0/node/buffer.ts";

//const type = "secp256k1";
const type = "secp256r1";
// Pick some curve
const curve = ecdh.getCurve(type);
		
// Choose algorithm to the hash function
const algorithm = 'sha256';

// Generate random keys for Alice
const aliceKeys = ecdh.generateKeys(curve);
	
// Hash something so we can have a digest to sign
const message = new Buffer('Hello World');
//const hash = crypto.createHash(algorithm).update(message).digest();
const hash = SHA256.digest(message);
console.log('Hashed message to sign:', hash.toString('hex'));

// Sign it with Alice's key
const signature = aliceKeys.privateKey.sign(hash, algorithm);
console.log('Signature:', signature.toString('hex'));

// Verify it with Alice public key
const valid = aliceKeys.publicKey.verifySignature(hash, signature);
console.log('Signature is', valid ? 'valid :)' : 'invalid!!');
