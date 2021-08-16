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

console.log('Alice public key:', aliceKeys.publicKey.buffer.toHexString());
console.log('Alice private key:', aliceKeys.privateKey.buffer.toHexString());
console.log('Bob public key:', bobKeys.publicKey.buffer.toHexString());
console.log('Bob private key:', bobKeys.privateKey.buffer.toHexString());

// Alice generate the shared secret:
const aliceSharedSecret = aliceKeys.privateKey.deriveSharedSecret(bobKeys.publicKey);
console.log('shared secret:', aliceSharedSecret.toHexString());

// Checking that Bob has the same secret:
const bobSharedSecret = bobKeys.privateKey.deriveSharedSecret(aliceKeys.publicKey);
const equals = (bobSharedSecret.toHexString() === aliceSharedSecret.toHexString());
console.log('Shared secrets are', equals ? 'equal :)' : 'not equal!!');

//zero-out all secure surfaces

aliceSharedSecret.zero();
bobSharedSecret.zero();

aliceKeys.publicKey.zero();
aliceKeys.privateKey.zero();

bobKeys.publicKey.zero();
bobKeys.privateKey.zero();
