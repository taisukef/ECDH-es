//import crypto from "https://deno.land/std@0.104.0/node/crypto.ts";
import { Buffer } from "https://taisukef.github.io/buffer/Buffer.js";

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

// randam

export const MAX_RANDOM_VALUES = 65536;
export const MAX_SIZE = 4294967295;

const generateRandomBytes = (size) => {
  if (size > MAX_SIZE) {
    throw new RangeError(
      `The value of "size" is out of range. It must be >= 0 && <= ${MAX_SIZE}. Received ${size}`,
    );
  }
  const bytes = Buffer.allocUnsafe(size);
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

const randomBytes = (size, cb, buf) => {
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

export { createHmac, randomBytes };
