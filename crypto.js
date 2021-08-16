//import crypto from "https://deno.land/std@0.104.0/node/crypto.ts";

/*
import { HMAC } from "https://deno.land/x/hmac@v2.0.1/mod.ts";
import { SHA256 } from "https://deno.land/x/hmac@v2.0.1/deps.ts";

crypto.createHmac = (algorithm, k) => {
	//const h = hmac(algorithm, k);
	//console.log("hmac", h);
	return new HMAC(new SHA256(), k);
};
*/

import { SHA256 } from "https://taisukef.github.io/sha256-es/SHA256.js";

//Detect if safe to run!
{
	var safe = false;
	if (typeof process !== 'undefined' && !!process.versions && !!process.versions.v8) {
		// V8 is considered safe because Uint8Array's
		// backing stores are allocated externally to
		// the heap and never move.
		safe = true;
	} else if (typeof Deno !== 'undefined') {
		//Deno is based on V8
		safe = true;
	} else if (typeof window !== 'undefined' && !!window.navigator && !!window.navigator.userAgent.match(/Chrome/)) {
		//Chrome is based on V8
		safe = true;
	}

	//X:TODO check the implementation of other engines

	if (!safe) {
		console.warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		console.warn("!!! This environment is not considered safe! USE WITH EXTREME CAUTION. !!!");
		console.warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}
}

var G_ZEROBUFFERS = [];
var G_BUFFER_DEBUG = false;

class ZeroableUint8Array extends Uint8Array {
	constructor(...args) {
		super(...args);
		if (G_BUFFER_DEBUG) {
			this.loc = new Error("Fault detected here");
			G_ZEROBUFFERS.push( this );
		}
	}

	static fromHexString(hexString, length) {
		if (!length) {
			throw new Error("`length` is required");
		}

		var za = new ZeroableUint8Array(length);
		za.writeHexString(hexString, 0, length);
		return za;
	}

	static setDebug(bool) {
		G_BUFFER_DEBUG = bool;
	}

	static debug() {
		if (G_ZEROBUFFERS.length) {
			console.log(G_ZEROBUFFERS[0].loc);
			throw new Error("Did not `zero()` all `ZeroableUint8Array`!");
		}
	}

	zero() {
		this.fill(0);
		if (!G_BUFFER_DEBUG) return;
		const idx = G_ZEROBUFFERS.indexOf( this );
		if (idx > -1) {
			G_ZEROBUFFERS.splice(idx, 1);
		} else {
			throw new Error("ZeroableUint8Array was already zeroed-out");
		}
	}

	writeHexString(hexString, pos, length) {
		var byteArray = hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
		
		if (!!length) {
			const remove = byteArray.length - length;
			if (remove < 0) {
				throw new RangeError(
					`The value of \`length\` is out of range. It must be > 0 && <= ${byteArray.length}. Received ${length}`,
				);
			} else {
				byteArray.splice(-remove, remove);
			}
		}

		this.set(byteArray, pos);
	}

	toHexString() {
		return this.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
	}
}


// RANDOM routines

export const MAX_RANDOM_VALUES = 65536;
export const MAX_SIZE = 4294967295;

const generateRandomBytes = (size) => {
	if (size > MAX_SIZE) {
		throw new RangeError(
			`The value of "size" is out of range. It must be >= 0 && <= ${MAX_SIZE}. Received ${size}`,
		);
	}
	const bytes = new ZeroableUint8Array(size);
	//Work around for getRandomValues max generation
	if (size > MAX_RANDOM_VALUES) {
		for (let generated = 0; generated < size; generated += MAX_RANDOM_VALUES) {
			crypto.getRandomValues(
				bytes.slice(generated, generated + MAX_RANDOM_VALUES),
			);
		}
	} else {
		crypto.getRandomValues(bytes);
	}
	return bytes;
}

const randomBytes = (size, cb) => {
	if (typeof cb === "function") {
		let err = null;
		let bytes;
		try {
			bytes = generateRandomBytes(size);
		} catch (e) {
			//NodeJS nonsense
			//If the size is out of range it will throw sync, otherwise throw async
			if (
				e instanceof RangeError &&
				e.message.includes('The value of "size" is out of range')
			) {
				throw e;
			} else {
				err = e;
			}
		}
		setTimeout(() => {
			if (err) {
				cb(err);
			} else {
				cb(null, bytes);
			}
		}, 0);
	} else {
		return generateRandomBytes(size);
	}
};

// SHA256

const concat = (a1, a2) => {
	const res = new Uint8Array(a1.length + a2.length);
	for (let i = 0; i < a1.length; i++) {
		res[i] = a1[i];
	}
	for (let i = 0; i < a2.length; i++) {
		res[i + a1.length] = a2[i];
	}
	return res;
};
class Hmac {
	constructor(bin) {
		this.data = new Uint8Array(bin.length);
	}
	update(bin) {
		//console.log("update", bin)
		this.data = concat(this.data, bin);
	}
	digest() {
		return SHA256.digest(this.data);
	}
};

const createHmac = (algorithm, k) => {
	if (algorithm != "sha256") {
		throw new Error("unsupported algorithm: " + algorithm);
	}
	return new Hmac(k);
};

export { createHmac, randomBytes, ZeroableUint8Array };
