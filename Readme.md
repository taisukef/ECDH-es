# ECDH-es

Pure JavaScript ES module implementation of ECDH and ECDSA for browsers and [Deno](https://deno.land/).

🚨 **Warning** 🚨 This library has not received any formal audit and is not considered safe for production use!

## Usage

```js
import { ECDH } from "https://taisukef.github.io/ECDH-es/ECDH.js";

const type = "secp256r1";
const curve = ECDH.getCurve(type);
const keys = ECDH.generateKeys(curve);
console.log(keys);
```

For usage details see the examples in the [examples](examples/) folder.

## Dependencies

- [SHA256](https://github.com/taisukef/sha256-es)
- [BigInteger](https://github.com/taisukef/jsbn-es)
- [Crypto.getRandomValues()](https://developer.mozilla.org/ja/docs/Web/API/Crypto/getRandomValues)

## Base project

forked from [developmentil/ecdh: Native Node.js module for ECDH and ECDSA.](https://github.com/developmentil/ecdh)
