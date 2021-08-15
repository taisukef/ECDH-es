import { ECDH } from "../ECDH.js";

// Pick some curve
const type = "secp256r1";
const curve = ECDH.getCurve(type);

// Generate random keys for Alice and Bob
const aliceKeys = ECDH.generateKeys(curve);
const bobKeys = ECDH.generateKeys(curve);

// Or you may get the keys from buffers:
//	aliceKeys = {
//		publicKey: ECDH.PublicKey.fromBuffer(curve, buf1),
//		privateKey: ECDH.PrivateKey.fromBuffer(curve, buf2)
//	};

console.log('Alice public key:', aliceKeys.publicKey.buffer.toString('hex'));
console.log('Alice private key:', aliceKeys.privateKey.buffer.toString('hex'));
console.log('Bob public key:', bobKeys.publicKey.buffer.toString('hex'));
console.log('Bob private key:', bobKeys.privateKey.buffer.toString('hex'));

// Alice generate the shared secret:
const aliceSharedSecret = aliceKeys.privateKey.deriveSharedSecret(bobKeys.publicKey);
console.log('shared secret:', aliceSharedSecret.toString('hex'));

// Checking that Bob has the same secret:
const bobSharedSecret = bobKeys.privateKey.deriveSharedSecret(aliceKeys.publicKey);
const equals = (bobSharedSecret.toString('hex') === aliceSharedSecret.toString('hex'));
console.log('Shared secrets are', equals ? 'equal :)' : 'not equal!!');
