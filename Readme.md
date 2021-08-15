# ECDH-es

Pure JavaScript ES module implementation of ECDH and ECDSA for browsers and [Deno](https://deno.langd/).

## Usage

```
import { ECDH } from "https://taisukef.github.io/ECDH-es/ECDH.js";

const type = "secp256r1";
const curve = ECDH.getCurve(type);
const keys = ECDH.generateKeys(curve);
console.log(keys);
```

For usage details see the examples in the examples folder.

## Base project

forked from [developmentil/ecdh: Native Node.js module for ECDH and ECDSA.](https://github.com/developmentil/ecdh)

## License

ecdh.js is freely distributable under the terms of the MIT license.

Copyright (c) 2014 Moshe Simantov

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
