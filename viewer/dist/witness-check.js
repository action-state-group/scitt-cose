(() => {
  // node_modules/cborg/lib/is.js
  var objectTypeNames = [
    "Object",
    "RegExp",
    "Date",
    "Error",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "ArrayBuffer",
    "SharedArrayBuffer",
    "DataView",
    "Promise",
    "URL",
    "HTMLElement",
    "Int8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
    "Tagged"
  ];
  function is(value) {
    if (value === null) {
      return "null";
    }
    if (value === undefined) {
      return "undefined";
    }
    if (value === true || value === false) {
      return "boolean";
    }
    const typeOf = typeof value;
    if (typeOf === "string" || typeOf === "number" || typeOf === "bigint" || typeOf === "symbol") {
      return typeOf;
    }
    if (typeOf === "function") {
      return "Function";
    }
    if (Array.isArray(value)) {
      return "Array";
    }
    if (value instanceof Uint8Array) {
      return "Uint8Array";
    }
    if (value.constructor === Object) {
      return "Object";
    }
    const objectType = getObjectType(value);
    if (objectType) {
      return objectType;
    }
    return "Object";
  }
  function getObjectType(value) {
    const objectTypeName = Object.prototype.toString.call(value).slice(8, -1);
    if (objectTypeNames.includes(objectTypeName)) {
      return objectTypeName;
    }
    return;
  }

  // node_modules/cborg/lib/token.js
  class Type {
    constructor(major, name, terminal) {
      this.major = major;
      this.majorEncoded = major << 5;
      this.name = name;
      this.terminal = terminal;
    }
    toString() {
      return `Type[${this.major}].${this.name}`;
    }
    compare(typ) {
      return this.major < typ.major ? -1 : this.major > typ.major ? 1 : 0;
    }
    static equals(a, b) {
      return a === b || a.major === b.major && a.name === b.name;
    }
  }
  Type.uint = new Type(0, "uint", true);
  Type.negint = new Type(1, "negint", true);
  Type.bytes = new Type(2, "bytes", true);
  Type.string = new Type(3, "string", true);
  Type.array = new Type(4, "array", false);
  Type.map = new Type(5, "map", false);
  Type.tag = new Type(6, "tag", false);
  Type.float = new Type(7, "float", true);
  Type.false = new Type(7, "false", true);
  Type.true = new Type(7, "true", true);
  Type.null = new Type(7, "null", true);
  Type.undefined = new Type(7, "undefined", true);
  Type.break = new Type(7, "break", true);

  class Token {
    constructor(type, value, encodedLength) {
      this.type = type;
      this.value = value;
      this.encodedLength = encodedLength;
      this.encodedBytes = undefined;
      this.byteValue = undefined;
    }
    toString() {
      return `Token[${this.type}].${this.value}`;
    }
  }

  // node_modules/cborg/lib/byte-utils.js
  var useBuffer = globalThis.process && !globalThis.process.browser && globalThis.Buffer && typeof globalThis.Buffer.isBuffer === "function";
  var textEncoder = new TextEncoder;
  function isBuffer(buf) {
    return useBuffer && globalThis.Buffer.isBuffer(buf);
  }
  function asU8A(buf) {
    if (!(buf instanceof Uint8Array)) {
      return Uint8Array.from(buf);
    }
    return isBuffer(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : buf;
  }
  var FROM_STRING_THRESHOLD_BUFFER = 24;
  var FROM_STRING_THRESHOLD_TEXTENCODER = 200;
  var fromString = useBuffer ? (string) => {
    return string.length >= FROM_STRING_THRESHOLD_BUFFER ? globalThis.Buffer.from(string) : utf8ToBytes(string);
  } : (string) => {
    return string.length >= FROM_STRING_THRESHOLD_TEXTENCODER ? textEncoder.encode(string) : utf8ToBytes(string);
  };
  var fromArray = (arr) => {
    return Uint8Array.from(arr);
  };
  var slice = useBuffer ? (bytes, start, end) => {
    if (isBuffer(bytes)) {
      return new Uint8Array(bytes.subarray(start, end));
    }
    return bytes.slice(start, end);
  } : (bytes, start, end) => {
    return bytes.slice(start, end);
  };
  var concat = useBuffer ? (chunks, length) => {
    chunks = chunks.map((c) => c instanceof Uint8Array ? c : globalThis.Buffer.from(c));
    return asU8A(globalThis.Buffer.concat(chunks, length));
  } : (chunks, length) => {
    const out = new Uint8Array(length);
    let off = 0;
    for (let b of chunks) {
      if (off + b.length > out.length) {
        b = b.subarray(0, out.length - off);
      }
      out.set(b, off);
      off += b.length;
    }
    return out;
  };
  var alloc = useBuffer ? (size) => {
    return globalThis.Buffer.allocUnsafe(size);
  } : (size) => {
    return new Uint8Array(size);
  };
  function compare(b1, b2) {
    if (isBuffer(b1) && isBuffer(b2)) {
      return b1.compare(b2);
    }
    for (let i = 0;i < b1.length; i++) {
      if (b1[i] === b2[i]) {
        continue;
      }
      return b1[i] < b2[i] ? -1 : 1;
    }
    return 0;
  }
  function utf8ToBytes(str) {
    const out = [];
    let p = 0;
    for (let i = 0;i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 128) {
        out[p++] = c;
      } else if (c < 2048) {
        out[p++] = c >> 6 | 192;
        out[p++] = c & 63 | 128;
      } else if ((c & 64512) === 55296 && i + 1 < str.length && (str.charCodeAt(i + 1) & 64512) === 56320) {
        c = 65536 + ((c & 1023) << 10) + (str.charCodeAt(++i) & 1023);
        out[p++] = c >> 18 | 240;
        out[p++] = c >> 12 & 63 | 128;
        out[p++] = c >> 6 & 63 | 128;
        out[p++] = c & 63 | 128;
      } else {
        if (c >= 55296 && c <= 57343) {
          c = 65533;
        }
        out[p++] = c >> 12 | 224;
        out[p++] = c >> 6 & 63 | 128;
        out[p++] = c & 63 | 128;
      }
    }
    return out;
  }

  // node_modules/cborg/lib/bl.js
  var defaultChunkSize = 256;

  class Bl {
    constructor(chunkSize = defaultChunkSize) {
      this.chunkSize = chunkSize;
      this.cursor = 0;
      this.maxCursor = -1;
      this.chunks = [];
      this._initReuseChunk = null;
    }
    reset() {
      this.cursor = 0;
      this.maxCursor = -1;
      if (this.chunks.length) {
        this.chunks = [];
      }
      if (this._initReuseChunk !== null) {
        this.chunks.push(this._initReuseChunk);
        this.maxCursor = this._initReuseChunk.length - 1;
      }
    }
    pushByte(byte) {
      let topChunk = this.chunks[this.chunks.length - 1];
      if (this.cursor > this.maxCursor) {
        topChunk = alloc(this.chunkSize);
        this.chunks.push(topChunk);
        this.maxCursor += topChunk.length;
        if (this._initReuseChunk === null) {
          this._initReuseChunk = topChunk;
        }
      }
      const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
      topChunk[chunkPos] = byte;
      this.cursor++;
    }
    push(bytes) {
      let topChunk = this.chunks[this.chunks.length - 1];
      const newMax = this.cursor + bytes.length;
      if (newMax <= this.maxCursor + 1) {
        const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
        topChunk.set(bytes, chunkPos);
      } else {
        if (topChunk) {
          const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
          if (chunkPos < topChunk.length) {
            this.chunks[this.chunks.length - 1] = topChunk.subarray(0, chunkPos);
            this.maxCursor = this.cursor - 1;
          }
        }
        if (bytes.length < 64 && bytes.length < this.chunkSize) {
          topChunk = alloc(this.chunkSize);
          this.chunks.push(topChunk);
          this.maxCursor += topChunk.length;
          if (this._initReuseChunk === null) {
            this._initReuseChunk = topChunk;
          }
          topChunk.set(bytes, 0);
        } else {
          this.chunks.push(bytes);
          this.maxCursor += bytes.length;
        }
      }
      this.cursor += bytes.length;
    }
    toBytes(reset = false) {
      let byts;
      if (this.chunks.length === 1) {
        const chunk = this.chunks[0];
        if (reset && this.cursor > chunk.length / 2) {
          byts = this.cursor === chunk.length ? chunk : chunk.subarray(0, this.cursor);
          this._initReuseChunk = null;
          this.chunks = [];
        } else {
          byts = slice(chunk, 0, this.cursor);
        }
      } else {
        byts = concat(this.chunks, this.cursor);
      }
      if (reset) {
        this.reset();
      }
      return byts;
    }
  }

  class U8Bl {
    constructor(dest) {
      this.dest = dest;
      this.cursor = 0;
      this.chunks = [dest];
    }
    reset() {
      this.cursor = 0;
    }
    pushByte(byte) {
      if (this.cursor >= this.dest.length) {
        throw new Error("write out of bounds, destination buffer is too small");
      }
      this.dest[this.cursor++] = byte;
    }
    push(bytes) {
      if (this.cursor + bytes.length > this.dest.length) {
        throw new Error("write out of bounds, destination buffer is too small");
      }
      this.dest.set(bytes, this.cursor);
      this.cursor += bytes.length;
    }
    toBytes(reset = false) {
      const byts = this.dest.subarray(0, this.cursor);
      if (reset) {
        this.reset();
      }
      return byts;
    }
  }

  // node_modules/cborg/lib/common.js
  var decodeErrPrefix = "CBOR decode error:";
  var encodeErrPrefix = "CBOR encode error:";
  var uintMinorPrefixBytes = [];
  uintMinorPrefixBytes[23] = 1;
  uintMinorPrefixBytes[24] = 2;
  uintMinorPrefixBytes[25] = 3;
  uintMinorPrefixBytes[26] = 5;
  uintMinorPrefixBytes[27] = 9;
  function assertEnoughData(data, pos, need) {
    if (data.length - pos < need) {
      throw new Error(`${decodeErrPrefix} not enough data for type`);
    }
  }

  // node_modules/cborg/lib/0uint.js
  var uintBoundaries = [24, 256, 65536, 4294967296, BigInt("18446744073709551616")];
  function readUint8(data, offset, options) {
    assertEnoughData(data, offset, 1);
    const value = data[offset];
    if (options.strict === true && value < uintBoundaries[0]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint16(data, offset, options) {
    assertEnoughData(data, offset, 2);
    const value = data[offset] << 8 | data[offset + 1];
    if (options.strict === true && value < uintBoundaries[1]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint32(data, offset, options) {
    assertEnoughData(data, offset, 4);
    const value = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
    if (options.strict === true && value < uintBoundaries[2]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    return value;
  }
  function readUint64(data, offset, options) {
    assertEnoughData(data, offset, 8);
    const hi = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
    const lo = data[offset + 4] * 16777216 + (data[offset + 5] << 16) + (data[offset + 6] << 8) + data[offset + 7];
    const value = (BigInt(hi) << BigInt(32)) + BigInt(lo);
    if (options.strict === true && value < uintBoundaries[3]) {
      throw new Error(`${decodeErrPrefix} integer encoded in more bytes than necessary (strict decode)`);
    }
    if (value <= Number.MAX_SAFE_INTEGER) {
      return Number(value);
    }
    if (options.allowBigInt === true) {
      return value;
    }
    throw new Error(`${decodeErrPrefix} integers outside of the safe integer range are not supported`);
  }
  function decodeUint8(data, pos, _minor, options) {
    return new Token(Type.uint, readUint8(data, pos + 1, options), 2);
  }
  function decodeUint16(data, pos, _minor, options) {
    return new Token(Type.uint, readUint16(data, pos + 1, options), 3);
  }
  function decodeUint32(data, pos, _minor, options) {
    return new Token(Type.uint, readUint32(data, pos + 1, options), 5);
  }
  function decodeUint64(data, pos, _minor, options) {
    return new Token(Type.uint, readUint64(data, pos + 1, options), 9);
  }
  function encodeUint(writer, token) {
    return encodeUintValue(writer, 0, token.value);
  }
  function encodeUintValue(writer, major, uint) {
    if (uint < uintBoundaries[0]) {
      const nuint = Number(uint);
      writer.pushByte(major | nuint);
    } else if (uint < uintBoundaries[1]) {
      const nuint = Number(uint);
      writer.push([major | 24, nuint]);
    } else if (uint < uintBoundaries[2]) {
      const nuint = Number(uint);
      writer.push([major | 25, nuint >>> 8, nuint & 255]);
    } else if (uint < uintBoundaries[3]) {
      const nuint = Number(uint);
      writer.push([major | 26, nuint >>> 24 & 255, nuint >>> 16 & 255, nuint >>> 8 & 255, nuint & 255]);
    } else {
      const buint = BigInt(uint);
      if (buint < uintBoundaries[4]) {
        const set = [major | 27, 0, 0, 0, 0, 0, 0, 0];
        let lo = Number(buint & BigInt(4294967295));
        let hi = Number(buint >> BigInt(32) & BigInt(4294967295));
        set[8] = lo & 255;
        lo = lo >> 8;
        set[7] = lo & 255;
        lo = lo >> 8;
        set[6] = lo & 255;
        lo = lo >> 8;
        set[5] = lo & 255;
        set[4] = hi & 255;
        hi = hi >> 8;
        set[3] = hi & 255;
        hi = hi >> 8;
        set[2] = hi & 255;
        hi = hi >> 8;
        set[1] = hi & 255;
        writer.push(set);
      } else {
        throw new Error(`${decodeErrPrefix} encountered BigInt larger than allowable range`);
      }
    }
  }
  encodeUint.encodedSize = function encodedSize(token) {
    return encodeUintValue.encodedSize(token.value);
  };
  encodeUintValue.encodedSize = function encodedSize2(uint) {
    if (uint < uintBoundaries[0]) {
      return 1;
    }
    if (uint < uintBoundaries[1]) {
      return 2;
    }
    if (uint < uintBoundaries[2]) {
      return 3;
    }
    if (uint < uintBoundaries[3]) {
      return 5;
    }
    return 9;
  };
  encodeUint.compareTokens = function compareTokens(tok1, tok2) {
    return tok1.value < tok2.value ? -1 : tok1.value > tok2.value ? 1 : 0;
  };

  // node_modules/cborg/lib/1negint.js
  function decodeNegint8(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint8(data, pos + 1, options), 2);
  }
  function decodeNegint16(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint16(data, pos + 1, options), 3);
  }
  function decodeNegint32(data, pos, _minor, options) {
    return new Token(Type.negint, -1 - readUint32(data, pos + 1, options), 5);
  }
  var neg1b = BigInt(-1);
  var pos1b = BigInt(1);
  function decodeNegint64(data, pos, _minor, options) {
    const int = readUint64(data, pos + 1, options);
    if (typeof int !== "bigint") {
      const value = -1 - int;
      if (value >= Number.MIN_SAFE_INTEGER) {
        return new Token(Type.negint, value, 9);
      }
    }
    if (options.allowBigInt !== true) {
      throw new Error(`${decodeErrPrefix} integers outside of the safe integer range are not supported`);
    }
    return new Token(Type.negint, neg1b - BigInt(int), 9);
  }
  function encodeNegint(writer, token) {
    const negint = token.value;
    const unsigned = typeof negint === "bigint" ? negint * neg1b - pos1b : negint * -1 - 1;
    encodeUintValue(writer, token.type.majorEncoded, unsigned);
  }
  encodeNegint.encodedSize = function encodedSize3(token) {
    const negint = token.value;
    const unsigned = typeof negint === "bigint" ? negint * neg1b - pos1b : negint * -1 - 1;
    if (unsigned < uintBoundaries[0]) {
      return 1;
    }
    if (unsigned < uintBoundaries[1]) {
      return 2;
    }
    if (unsigned < uintBoundaries[2]) {
      return 3;
    }
    if (unsigned < uintBoundaries[3]) {
      return 5;
    }
    return 9;
  };
  encodeNegint.compareTokens = function compareTokens2(tok1, tok2) {
    return tok1.value < tok2.value ? 1 : tok1.value > tok2.value ? -1 : 0;
  };

  // node_modules/cborg/lib/2bytes.js
  function toToken(data, pos, prefix, length) {
    assertEnoughData(data, pos, prefix + length);
    const buf = data.slice(pos + prefix, pos + prefix + length);
    return new Token(Type.bytes, buf, prefix + length);
  }
  function decodeBytesCompact(data, pos, minor, _options) {
    return toToken(data, pos, 1, minor);
  }
  function decodeBytes8(data, pos, _minor, options) {
    return toToken(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeBytes16(data, pos, _minor, options) {
    return toToken(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeBytes32(data, pos, _minor, options) {
    return toToken(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeBytes64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer bytes lengths not supported`);
    }
    return toToken(data, pos, 9, l);
  }
  function tokenBytes(token) {
    if (token.encodedBytes === undefined) {
      token.encodedBytes = Type.equals(token.type, Type.string) ? fromString(token.value) : token.value;
    }
    return token.encodedBytes;
  }
  function encodeBytes(writer, token) {
    const bytes = tokenBytes(token);
    encodeUintValue(writer, token.type.majorEncoded, bytes.length);
    writer.push(bytes);
  }
  encodeBytes.encodedSize = function encodedSize4(token) {
    const bytes = tokenBytes(token);
    return encodeUintValue.encodedSize(bytes.length) + bytes.length;
  };
  encodeBytes.compareTokens = function compareTokens3(tok1, tok2) {
    return compareBytes(tokenBytes(tok1), tokenBytes(tok2));
  };
  function compareBytes(b1, b2) {
    return b1.length < b2.length ? -1 : b1.length > b2.length ? 1 : compare(b1, b2);
  }

  // node_modules/cborg/lib/3string.js
  var textDecoder = new TextDecoder;
  var ASCII_THRESHOLD = 32;
  function toStr(bytes, start, end) {
    const len = end - start;
    if (len < ASCII_THRESHOLD) {
      let str = "";
      for (let i = start;i < end; i++) {
        const c = bytes[i];
        if (c & 128) {
          return textDecoder.decode(bytes.subarray(start, end));
        }
        str += String.fromCharCode(c);
      }
      return str;
    }
    return textDecoder.decode(bytes.subarray(start, end));
  }
  function toToken2(data, pos, prefix, length, options) {
    const totLength = prefix + length;
    assertEnoughData(data, pos, totLength);
    const tok = new Token(Type.string, toStr(data, pos + prefix, pos + totLength), totLength);
    if (options.retainStringBytes === true) {
      tok.byteValue = data.slice(pos + prefix, pos + totLength);
    }
    return tok;
  }
  function decodeStringCompact(data, pos, minor, options) {
    return toToken2(data, pos, 1, minor, options);
  }
  function decodeString8(data, pos, _minor, options) {
    return toToken2(data, pos, 2, readUint8(data, pos + 1, options), options);
  }
  function decodeString16(data, pos, _minor, options) {
    return toToken2(data, pos, 3, readUint16(data, pos + 1, options), options);
  }
  function decodeString32(data, pos, _minor, options) {
    return toToken2(data, pos, 5, readUint32(data, pos + 1, options), options);
  }
  function decodeString64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer string lengths not supported`);
    }
    return toToken2(data, pos, 9, l, options);
  }
  var encodeString = encodeBytes;

  // node_modules/cborg/lib/4array.js
  function toToken3(_data, _pos, prefix, length) {
    return new Token(Type.array, length, prefix);
  }
  function decodeArrayCompact(data, pos, minor, _options) {
    return toToken3(data, pos, 1, minor);
  }
  function decodeArray8(data, pos, _minor, options) {
    return toToken3(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeArray16(data, pos, _minor, options) {
    return toToken3(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeArray32(data, pos, _minor, options) {
    return toToken3(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeArray64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer array lengths not supported`);
    }
    return toToken3(data, pos, 9, l);
  }
  function decodeArrayIndefinite(data, pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return toToken3(data, pos, 1, Infinity);
  }
  function encodeArray(writer, token) {
    encodeUintValue(writer, Type.array.majorEncoded, token.value);
  }
  encodeArray.compareTokens = encodeUint.compareTokens;
  encodeArray.encodedSize = function encodedSize5(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/5map.js
  function toToken4(_data, _pos, prefix, length) {
    return new Token(Type.map, length, prefix);
  }
  function decodeMapCompact(data, pos, minor, _options) {
    return toToken4(data, pos, 1, minor);
  }
  function decodeMap8(data, pos, _minor, options) {
    return toToken4(data, pos, 2, readUint8(data, pos + 1, options));
  }
  function decodeMap16(data, pos, _minor, options) {
    return toToken4(data, pos, 3, readUint16(data, pos + 1, options));
  }
  function decodeMap32(data, pos, _minor, options) {
    return toToken4(data, pos, 5, readUint32(data, pos + 1, options));
  }
  function decodeMap64(data, pos, _minor, options) {
    const l = readUint64(data, pos + 1, options);
    if (typeof l === "bigint") {
      throw new Error(`${decodeErrPrefix} 64-bit integer map lengths not supported`);
    }
    return toToken4(data, pos, 9, l);
  }
  function decodeMapIndefinite(data, pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return toToken4(data, pos, 1, Infinity);
  }
  function encodeMap(writer, token) {
    encodeUintValue(writer, Type.map.majorEncoded, token.value);
  }
  encodeMap.compareTokens = encodeUint.compareTokens;
  encodeMap.encodedSize = function encodedSize6(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/6tag.js
  function decodeTagCompact(_data, _pos, minor, _options) {
    return new Token(Type.tag, minor, 1);
  }
  function decodeTag8(data, pos, _minor, options) {
    return new Token(Type.tag, readUint8(data, pos + 1, options), 2);
  }
  function decodeTag16(data, pos, _minor, options) {
    return new Token(Type.tag, readUint16(data, pos + 1, options), 3);
  }
  function decodeTag32(data, pos, _minor, options) {
    return new Token(Type.tag, readUint32(data, pos + 1, options), 5);
  }
  function decodeTag64(data, pos, _minor, options) {
    return new Token(Type.tag, readUint64(data, pos + 1, options), 9);
  }
  function encodeTag(writer, token) {
    encodeUintValue(writer, Type.tag.majorEncoded, token.value);
  }
  encodeTag.compareTokens = encodeUint.compareTokens;
  encodeTag.encodedSize = function encodedSize7(token) {
    return encodeUintValue.encodedSize(token.value);
  };

  // node_modules/cborg/lib/7float.js
  var MINOR_FALSE = 20;
  var MINOR_TRUE = 21;
  var MINOR_NULL = 22;
  var MINOR_UNDEFINED = 23;
  function decodeUndefined(_data, _pos, _minor, options) {
    if (options.allowUndefined === false) {
      throw new Error(`${decodeErrPrefix} undefined values are not supported`);
    } else if (options.coerceUndefinedToNull === true) {
      return new Token(Type.null, null, 1);
    }
    return new Token(Type.undefined, undefined, 1);
  }
  function decodeBreak(_data, _pos, _minor, options) {
    if (options.allowIndefinite === false) {
      throw new Error(`${decodeErrPrefix} indefinite length items not allowed`);
    }
    return new Token(Type.break, undefined, 1);
  }
  function createToken(value, bytes, options) {
    if (options) {
      if (options.allowNaN === false && Number.isNaN(value)) {
        throw new Error(`${decodeErrPrefix} NaN values are not supported`);
      }
      if (options.allowInfinity === false && (value === Infinity || value === -Infinity)) {
        throw new Error(`${decodeErrPrefix} Infinity values are not supported`);
      }
    }
    return new Token(Type.float, value, bytes);
  }
  function decodeFloat16(data, pos, _minor, options) {
    return createToken(readFloat16(data, pos + 1), 3, options);
  }
  function decodeFloat32(data, pos, _minor, options) {
    return createToken(readFloat32(data, pos + 1), 5, options);
  }
  function decodeFloat64(data, pos, _minor, options) {
    return createToken(readFloat64(data, pos + 1), 9, options);
  }
  function encodeFloat(writer, token, options) {
    const float = token.value;
    if (float === false) {
      writer.pushByte(Type.float.majorEncoded | MINOR_FALSE);
    } else if (float === true) {
      writer.pushByte(Type.float.majorEncoded | MINOR_TRUE);
    } else if (float === null) {
      writer.pushByte(Type.float.majorEncoded | MINOR_NULL);
    } else if (float === undefined) {
      writer.pushByte(Type.float.majorEncoded | MINOR_UNDEFINED);
    } else {
      let decoded;
      let success = false;
      if (!options || options.float64 !== true) {
        encodeFloat16(float);
        decoded = readFloat16(ui8a, 1);
        if (float === decoded || Number.isNaN(float)) {
          ui8a[0] = 249;
          writer.push(ui8a.slice(0, 3));
          success = true;
        } else {
          encodeFloat32(float);
          decoded = readFloat32(ui8a, 1);
          if (float === decoded) {
            ui8a[0] = 250;
            writer.push(ui8a.slice(0, 5));
            success = true;
          }
        }
      }
      if (!success) {
        encodeFloat64(float);
        decoded = readFloat64(ui8a, 1);
        ui8a[0] = 251;
        writer.push(ui8a.slice(0, 9));
      }
    }
  }
  encodeFloat.encodedSize = function encodedSize8(token, options) {
    const float = token.value;
    if (float === false || float === true || float === null || float === undefined) {
      return 1;
    }
    if (!options || options.float64 !== true) {
      encodeFloat16(float);
      let decoded = readFloat16(ui8a, 1);
      if (float === decoded || Number.isNaN(float)) {
        return 3;
      }
      encodeFloat32(float);
      decoded = readFloat32(ui8a, 1);
      if (float === decoded) {
        return 5;
      }
    }
    return 9;
  };
  var buffer = new ArrayBuffer(9);
  var dataView = new DataView(buffer, 1);
  var ui8a = new Uint8Array(buffer, 0);
  function encodeFloat16(inp) {
    if (inp === Infinity) {
      dataView.setUint16(0, 31744, false);
    } else if (inp === -Infinity) {
      dataView.setUint16(0, 64512, false);
    } else if (Number.isNaN(inp)) {
      dataView.setUint16(0, 32256, false);
    } else {
      dataView.setFloat32(0, inp);
      const valu32 = dataView.getUint32(0);
      const exponent = (valu32 & 2139095040) >> 23;
      const mantissa = valu32 & 8388607;
      if (exponent === 255) {
        dataView.setUint16(0, 31744, false);
      } else if (exponent === 0) {
        dataView.setUint16(0, (valu32 & 2147483648) >> 16 | mantissa >> 13, false);
      } else {
        const logicalExponent = exponent - 127;
        if (logicalExponent < -24) {
          dataView.setUint16(0, 0);
        } else if (logicalExponent < -14) {
          dataView.setUint16(0, (valu32 & 2147483648) >> 16 | 1 << 24 + logicalExponent, false);
        } else {
          dataView.setUint16(0, (valu32 & 2147483648) >> 16 | logicalExponent + 15 << 10 | mantissa >> 13, false);
        }
      }
    }
  }
  function readFloat16(ui8a2, pos) {
    if (ui8a2.length - pos < 2) {
      throw new Error(`${decodeErrPrefix} not enough data for float16`);
    }
    const half = (ui8a2[pos] << 8) + ui8a2[pos + 1];
    if (half === 31744) {
      return Infinity;
    }
    if (half === 64512) {
      return -Infinity;
    }
    if (half === 32256) {
      return NaN;
    }
    const exp = half >> 10 & 31;
    const mant = half & 1023;
    let val;
    if (exp === 0) {
      val = mant * 2 ** -24;
    } else if (exp !== 31) {
      val = (mant + 1024) * 2 ** (exp - 25);
    } else {
      val = mant === 0 ? Infinity : NaN;
    }
    return half & 32768 ? -val : val;
  }
  function encodeFloat32(inp) {
    dataView.setFloat32(0, inp, false);
  }
  function readFloat32(ui8a2, pos) {
    if (ui8a2.length - pos < 4) {
      throw new Error(`${decodeErrPrefix} not enough data for float32`);
    }
    const offset = (ui8a2.byteOffset || 0) + pos;
    return new DataView(ui8a2.buffer, offset, 4).getFloat32(0, false);
  }
  function encodeFloat64(inp) {
    dataView.setFloat64(0, inp, false);
  }
  function readFloat64(ui8a2, pos) {
    if (ui8a2.length - pos < 8) {
      throw new Error(`${decodeErrPrefix} not enough data for float64`);
    }
    const offset = (ui8a2.byteOffset || 0) + pos;
    return new DataView(ui8a2.buffer, offset, 8).getFloat64(0, false);
  }
  function encodeMajorSevenBytes(token, float64) {
    const float = token.value;
    if (float === false) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_FALSE);
    }
    if (float === true) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_TRUE);
    }
    if (float === null) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_NULL);
    }
    if (float === undefined) {
      return Uint8Array.of(Type.float.majorEncoded | MINOR_UNDEFINED);
    }
    if (!float64) {
      encodeFloat16(float);
      if (float === readFloat16(ui8a, 1) || Number.isNaN(float)) {
        ui8a[0] = 249;
        return ui8a.slice(0, 3);
      }
      encodeFloat32(float);
      if (float === readFloat32(ui8a, 1)) {
        ui8a[0] = 250;
        return ui8a.slice(0, 5);
      }
    }
    encodeFloat64(float);
    ui8a[0] = 251;
    return ui8a.slice(0, 9);
  }
  function majorSevenBytes(token, options) {
    const tokenEx = token;
    const float64 = options?.float64 === true;
    const cached = float64 ? tokenEx._keyBytesFloat64 : tokenEx._keyBytes;
    if (cached !== undefined) {
      return cached;
    }
    const bytes = encodeMajorSevenBytes(token, float64);
    if (float64) {
      tokenEx._keyBytesFloat64 = bytes;
    } else {
      tokenEx._keyBytes = bytes;
    }
    return bytes;
  }
  encodeFloat.compareTokens = function compareTokens4(tok1, tok2, options) {
    const b1 = majorSevenBytes(tok1, options);
    const b2 = majorSevenBytes(tok2, options);
    if (b1.length !== b2.length) {
      return b1.length < b2.length ? -1 : 1;
    }
    return compare(b1, b2);
  };

  // node_modules/cborg/lib/jump.js
  function invalidMinor(data, pos, minor) {
    throw new Error(`${decodeErrPrefix} encountered invalid minor (${minor}) for major ${data[pos] >>> 5}`);
  }
  function errorer(msg) {
    return () => {
      throw new Error(`${decodeErrPrefix} ${msg}`);
    };
  }
  var jump = [];
  for (let i = 0;i <= 23; i++) {
    jump[i] = invalidMinor;
  }
  jump[24] = decodeUint8;
  jump[25] = decodeUint16;
  jump[26] = decodeUint32;
  jump[27] = decodeUint64;
  jump[28] = invalidMinor;
  jump[29] = invalidMinor;
  jump[30] = invalidMinor;
  jump[31] = invalidMinor;
  for (let i = 32;i <= 55; i++) {
    jump[i] = invalidMinor;
  }
  jump[56] = decodeNegint8;
  jump[57] = decodeNegint16;
  jump[58] = decodeNegint32;
  jump[59] = decodeNegint64;
  jump[60] = invalidMinor;
  jump[61] = invalidMinor;
  jump[62] = invalidMinor;
  jump[63] = invalidMinor;
  for (let i = 64;i <= 87; i++) {
    jump[i] = decodeBytesCompact;
  }
  jump[88] = decodeBytes8;
  jump[89] = decodeBytes16;
  jump[90] = decodeBytes32;
  jump[91] = decodeBytes64;
  jump[92] = invalidMinor;
  jump[93] = invalidMinor;
  jump[94] = invalidMinor;
  jump[95] = errorer("indefinite length bytes/strings are not supported");
  for (let i = 96;i <= 119; i++) {
    jump[i] = decodeStringCompact;
  }
  jump[120] = decodeString8;
  jump[121] = decodeString16;
  jump[122] = decodeString32;
  jump[123] = decodeString64;
  jump[124] = invalidMinor;
  jump[125] = invalidMinor;
  jump[126] = invalidMinor;
  jump[127] = errorer("indefinite length bytes/strings are not supported");
  for (let i = 128;i <= 151; i++) {
    jump[i] = decodeArrayCompact;
  }
  jump[152] = decodeArray8;
  jump[153] = decodeArray16;
  jump[154] = decodeArray32;
  jump[155] = decodeArray64;
  jump[156] = invalidMinor;
  jump[157] = invalidMinor;
  jump[158] = invalidMinor;
  jump[159] = decodeArrayIndefinite;
  for (let i = 160;i <= 183; i++) {
    jump[i] = decodeMapCompact;
  }
  jump[184] = decodeMap8;
  jump[185] = decodeMap16;
  jump[186] = decodeMap32;
  jump[187] = decodeMap64;
  jump[188] = invalidMinor;
  jump[189] = invalidMinor;
  jump[190] = invalidMinor;
  jump[191] = decodeMapIndefinite;
  for (let i = 192;i <= 215; i++) {
    jump[i] = decodeTagCompact;
  }
  jump[216] = decodeTag8;
  jump[217] = decodeTag16;
  jump[218] = decodeTag32;
  jump[219] = decodeTag64;
  jump[220] = invalidMinor;
  jump[221] = invalidMinor;
  jump[222] = invalidMinor;
  jump[223] = invalidMinor;
  for (let i = 224;i <= 243; i++) {
    jump[i] = errorer("simple values are not supported");
  }
  jump[244] = invalidMinor;
  jump[245] = invalidMinor;
  jump[246] = invalidMinor;
  jump[247] = decodeUndefined;
  jump[248] = errorer("simple values are not supported");
  jump[249] = decodeFloat16;
  jump[250] = decodeFloat32;
  jump[251] = decodeFloat64;
  jump[252] = invalidMinor;
  jump[253] = invalidMinor;
  jump[254] = invalidMinor;
  jump[255] = decodeBreak;
  var quick = [];
  for (let i = 0;i < 24; i++) {
    quick[i] = new Token(Type.uint, i, 1);
  }
  for (let i = -1;i >= -24; i--) {
    quick[31 - i] = new Token(Type.negint, i, 1);
  }
  quick[64] = new Token(Type.bytes, new Uint8Array(0), 1);
  quick[96] = new Token(Type.string, "", 1);
  quick[128] = new Token(Type.array, 0, 1);
  quick[160] = new Token(Type.map, 0, 1);
  quick[244] = new Token(Type.false, false, 1);
  quick[245] = new Token(Type.true, true, 1);
  quick[246] = new Token(Type.null, null, 1);
  function quickEncodeToken(token) {
    switch (token.type) {
      case Type.false:
        return fromArray([244]);
      case Type.true:
        return fromArray([245]);
      case Type.null:
        return fromArray([246]);
      case Type.bytes:
        if (!token.value.length) {
          return fromArray([64]);
        }
        return;
      case Type.string:
        if (token.value === "") {
          return fromArray([96]);
        }
        return;
      case Type.array:
        if (token.value === 0) {
          return fromArray([128]);
        }
        return;
      case Type.map:
        if (token.value === 0) {
          return fromArray([160]);
        }
        return;
      case Type.uint:
        if (token.value < 24) {
          return fromArray([Number(token.value)]);
        }
        return;
      case Type.negint:
        if (token.value >= -24) {
          return fromArray([31 - Number(token.value)]);
        }
    }
  }

  // node_modules/cborg/lib/encode.js
  var defaultEncodeOptions = {
    float64: false,
    mapSorter,
    quickEncodeToken
  };
  var rfc8949EncodeOptions = Object.freeze({
    mapSorter: rfc8949MapSorter,
    quickEncodeToken
  });
  function makeCborEncoders() {
    const encoders = [];
    encoders[Type.uint.major] = encodeUint;
    encoders[Type.negint.major] = encodeNegint;
    encoders[Type.bytes.major] = encodeBytes;
    encoders[Type.string.major] = encodeString;
    encoders[Type.array.major] = encodeArray;
    encoders[Type.map.major] = encodeMap;
    encoders[Type.tag.major] = encodeTag;
    encoders[Type.float.major] = encodeFloat;
    return encoders;
  }
  var cborEncoders = makeCborEncoders();
  var defaultWriter = new Bl;

  class Ref {
    constructor(obj, parent) {
      this.obj = obj;
      this.parent = parent;
    }
    includes(obj) {
      let p = this;
      do {
        if (p.obj === obj) {
          return true;
        }
      } while (p = p.parent);
      return false;
    }
    static createCheck(stack, obj) {
      if (stack && stack.includes(obj)) {
        throw new Error(`${encodeErrPrefix} object contains circular references`);
      }
      return new Ref(obj, stack);
    }
  }
  var simpleTokens = {
    null: new Token(Type.null, null),
    undefined: new Token(Type.undefined, undefined),
    true: new Token(Type.true, true),
    false: new Token(Type.false, false),
    emptyArray: new Token(Type.array, 0),
    emptyMap: new Token(Type.map, 0)
  };
  var typeEncoders = {
    number(obj, _typ, _options, _refStack) {
      if (!Number.isInteger(obj) || !Number.isSafeInteger(obj)) {
        return new Token(Type.float, obj);
      } else if (obj >= 0) {
        return new Token(Type.uint, obj);
      } else {
        return new Token(Type.negint, obj);
      }
    },
    bigint(obj, _typ, _options, _refStack) {
      if (obj >= BigInt(0)) {
        return new Token(Type.uint, obj);
      } else {
        return new Token(Type.negint, obj);
      }
    },
    Uint8Array(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, obj);
    },
    string(obj, _typ, _options, _refStack) {
      return new Token(Type.string, obj);
    },
    boolean(obj, _typ, _options, _refStack) {
      return obj ? simpleTokens.true : simpleTokens.false;
    },
    null(_obj, _typ, _options, _refStack) {
      return simpleTokens.null;
    },
    undefined(_obj, _typ, _options, _refStack) {
      return simpleTokens.undefined;
    },
    ArrayBuffer(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, new Uint8Array(obj));
    },
    DataView(obj, _typ, _options, _refStack) {
      return new Token(Type.bytes, new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength));
    },
    Array(obj, _typ, options, refStack) {
      if (!obj.length) {
        if (options.addBreakTokens === true) {
          return [simpleTokens.emptyArray, new Token(Type.break)];
        }
        return simpleTokens.emptyArray;
      }
      refStack = Ref.createCheck(refStack, obj);
      const entries = [];
      let i = 0;
      for (const e of obj) {
        entries[i++] = objectToTokens(e, options, refStack);
      }
      if (options.addBreakTokens) {
        return [new Token(Type.array, obj.length), entries, new Token(Type.break)];
      }
      return [new Token(Type.array, obj.length), entries];
    },
    Object(obj, typ, options, refStack) {
      const isMap = typ !== "Object";
      const keys = isMap ? obj.keys() : Object.keys(obj);
      const maxLength = isMap ? obj.size : keys.length;
      let entries;
      if (maxLength) {
        entries = new Array(maxLength);
        refStack = Ref.createCheck(refStack, obj);
        const skipUndefined = !isMap && options.ignoreUndefinedProperties;
        let i = 0;
        for (const key of keys) {
          const value = isMap ? obj.get(key) : obj[key];
          if (skipUndefined && value === undefined) {
            continue;
          }
          entries[i++] = [
            objectToTokens(key, options, refStack),
            objectToTokens(value, options, refStack)
          ];
        }
        if (i < maxLength) {
          entries.length = i;
        }
      }
      if (!entries?.length) {
        if (options.addBreakTokens === true) {
          return [simpleTokens.emptyMap, new Token(Type.break)];
        }
        return simpleTokens.emptyMap;
      }
      sortMapEntries(entries, options);
      if (options.addBreakTokens) {
        return [new Token(Type.map, entries.length), entries, new Token(Type.break)];
      }
      return [new Token(Type.map, entries.length), entries];
    },
    Tagged(obj, _typ, options, refStack) {
      return [
        new Token(Type.tag, obj.tag),
        objectToTokens(obj.value, options, refStack)
      ];
    }
  };
  typeEncoders.Map = typeEncoders.Object;
  typeEncoders.Buffer = typeEncoders.Uint8Array;
  for (const typ of "Uint8Clamped Uint16 Uint32 Int8 Int16 Int32 BigUint64 BigInt64 Float32 Float64".split(" ")) {
    typeEncoders[`${typ}Array`] = typeEncoders.DataView;
  }
  function objectToTokens(obj, options = {}, refStack) {
    const typ = is(obj);
    const customTypeEncoder = options && options.typeEncoders && options.typeEncoders[typ] || typeEncoders[typ];
    if (typeof customTypeEncoder === "function") {
      const tokens = customTypeEncoder(obj, typ, options, refStack);
      if (tokens != null) {
        return tokens;
      }
    }
    const typeEncoder = typeEncoders[typ];
    if (!typeEncoder) {
      throw new Error(`${encodeErrPrefix} unsupported type: ${typ}`);
    }
    return typeEncoder(obj, typ, options, refStack);
  }
  function sortMapEntries(entries, options) {
    const mapSorter = options.mapSorter;
    if (mapSorter) {
      entries.sort((e1, e2) => mapSorter(e1, e2, options));
    }
  }
  function mapSorter(e1, e2, options) {
    const keyToken1 = Array.isArray(e1[0]) ? e1[0][0] : e1[0];
    const keyToken2 = Array.isArray(e2[0]) ? e2[0][0] : e2[0];
    if (keyToken1.type.major !== keyToken2.type.major) {
      return keyToken1.type.compare(keyToken2.type);
    }
    const major = keyToken1.type.major;
    const tcmp = cborEncoders[major].compareTokens(keyToken1, keyToken2, options);
    if (tcmp === 0) {
      console.warn("WARNING: complex key types used, CBOR key sorting guarantees are gone");
    }
    return tcmp;
  }
  function rfc8949MapSorter(e1, e2) {
    if (e1[0] instanceof Token && e2[0] instanceof Token) {
      const t1 = e1[0];
      const t2 = e2[0];
      if (!t1._keyBytes) {
        t1._keyBytes = encodeRfc8949(t1.value);
      }
      if (!t2._keyBytes) {
        t2._keyBytes = encodeRfc8949(t2.value);
      }
      return compare(t1._keyBytes, t2._keyBytes);
    }
    throw new Error("rfc8949MapSorter: complex key types are not supported yet");
  }
  function encodeRfc8949(data) {
    return encodeCustom(data, cborEncoders, rfc8949EncodeOptions);
  }
  function tokensToEncoded(writer, tokens, encoders, options) {
    if (Array.isArray(tokens)) {
      for (const token of tokens) {
        tokensToEncoded(writer, token, encoders, options);
      }
    } else {
      encoders[tokens.type.major](writer, tokens, options);
    }
  }
  var MAJOR_UINT = Type.uint.majorEncoded;
  var MAJOR_NEGINT = Type.negint.majorEncoded;
  var MAJOR_BYTES = Type.bytes.majorEncoded;
  var MAJOR_STRING = Type.string.majorEncoded;
  var MAJOR_ARRAY = Type.array.majorEncoded;
  var MAJOR_MAP = Type.map.majorEncoded;
  var SIMPLE_FALSE = Type.float.majorEncoded | MINOR_FALSE;
  var SIMPLE_TRUE = Type.float.majorEncoded | MINOR_TRUE;
  var SIMPLE_NULL = Type.float.majorEncoded | MINOR_NULL;
  var SIMPLE_UNDEFINED = Type.float.majorEncoded | MINOR_UNDEFINED;
  var neg1b2 = BigInt(-1);
  var pos1b2 = BigInt(1);
  function directEncodeUintValue(writer, major, uint) {
    if (uint < 24) {
      writer.pushByte(major | Number(uint));
    } else {
      encodeUintValue(writer, major, uint);
    }
  }
  function canDirectEncode(options) {
    return options.addBreakTokens !== true;
  }
  function directEncodeMap(writer, data, typ, options, refStack) {
    const isMap = typ === "Map";
    const keys = isMap ? data.keys() : Object.keys(data);
    const maxLength = isMap ? data.size : keys.length;
    if (!maxLength) {
      writer.pushByte(MAJOR_MAP);
      return;
    }
    refStack = Ref.createCheck(refStack, data);
    const skipUndefined = !isMap && options.ignoreUndefinedProperties;
    const entries = new Array(maxLength);
    let length = 0;
    for (const key of keys) {
      const value = isMap ? data.get(key) : data[key];
      if (skipUndefined && value === undefined) {
        continue;
      }
      entries[length++] = [objectToTokens(key, options, refStack), value];
    }
    if (length === 0) {
      writer.pushByte(MAJOR_MAP);
      return;
    }
    if (length < maxLength) {
      entries.length = length;
    }
    entries.sort((e1, e2) => mapSorter(e1, e2, options));
    directEncodeUintValue(writer, MAJOR_MAP, length);
    for (const [key, value] of entries) {
      tokensToEncoded(writer, key, cborEncoders, options);
      directEncode(writer, value, options, refStack);
    }
  }
  function directEncode(writer, data, options, refStack) {
    const typ = is(data);
    const customEncoder = options.typeEncoders && options.typeEncoders[typ];
    if (customEncoder) {
      const tokens = customEncoder(data, typ, options, refStack);
      if (tokens != null) {
        tokensToEncoded(writer, tokens, cborEncoders, options);
        return;
      }
    }
    switch (typ) {
      case "null":
        writer.pushByte(SIMPLE_NULL);
        return;
      case "undefined":
        writer.pushByte(SIMPLE_UNDEFINED);
        return;
      case "boolean":
        writer.pushByte(data ? SIMPLE_TRUE : SIMPLE_FALSE);
        return;
      case "number":
        if (!Number.isInteger(data) || !Number.isSafeInteger(data)) {
          encodeFloat(writer, new Token(Type.float, data), options);
        } else if (data >= 0) {
          directEncodeUintValue(writer, MAJOR_UINT, data);
        } else {
          directEncodeUintValue(writer, MAJOR_NEGINT, data * -1 - 1);
        }
        return;
      case "bigint":
        if (data >= BigInt(0)) {
          directEncodeUintValue(writer, MAJOR_UINT, data);
        } else {
          directEncodeUintValue(writer, MAJOR_NEGINT, data * neg1b2 - pos1b2);
        }
        return;
      case "string": {
        const bytes = fromString(data);
        directEncodeUintValue(writer, MAJOR_STRING, bytes.length);
        writer.push(bytes);
        return;
      }
      case "Uint8Array":
        directEncodeUintValue(writer, MAJOR_BYTES, data.length);
        writer.push(data);
        return;
      case "Array":
        if (!data.length) {
          writer.pushByte(MAJOR_ARRAY);
          return;
        }
        refStack = Ref.createCheck(refStack, data);
        directEncodeUintValue(writer, MAJOR_ARRAY, data.length);
        for (const elem of data) {
          directEncode(writer, elem, options, refStack);
        }
        return;
      case "Object":
      case "Map":
        if (options.mapSorter === mapSorter) {
          directEncodeMap(writer, data, typ, options, refStack);
        } else {
          const tokens = typeEncoders.Object(data, typ, options, refStack);
          tokensToEncoded(writer, tokens, cborEncoders, options);
        }
        return;
      default: {
        const typeEncoder = typeEncoders[typ];
        if (!typeEncoder) {
          throw new Error(`${encodeErrPrefix} unsupported type: ${typ}`);
        }
        const tokens = typeEncoder(data, typ, options, refStack);
        tokensToEncoded(writer, tokens, cborEncoders, options);
      }
    }
  }
  function encodeCustom(data, encoders, options, destination) {
    const hasDest = destination instanceof Uint8Array;
    let writeTo = hasDest ? new U8Bl(destination) : defaultWriter;
    const tokens = objectToTokens(data, options);
    if (!Array.isArray(tokens) && options.quickEncodeToken) {
      const quickBytes = options.quickEncodeToken(tokens);
      if (quickBytes) {
        if (hasDest) {
          writeTo.push(quickBytes);
          return writeTo.toBytes();
        }
        return quickBytes;
      }
      const encoder = encoders[tokens.type.major];
      if (encoder.encodedSize) {
        const size = encoder.encodedSize(tokens, options);
        if (!hasDest) {
          writeTo = new Bl(size);
        }
        encoder(writeTo, tokens, options);
        if (writeTo.chunks.length !== 1) {
          throw new Error(`Unexpected error: pre-calculated length for ${tokens} was wrong`);
        }
        return hasDest ? writeTo.toBytes() : asU8A(writeTo.chunks[0]);
      }
    }
    writeTo.reset();
    tokensToEncoded(writeTo, tokens, encoders, options);
    return writeTo.toBytes(true);
  }
  function encode(data, options) {
    options = Object.assign({}, defaultEncodeOptions, options);
    if (canDirectEncode(options)) {
      defaultWriter.reset();
      directEncode(defaultWriter, data, options, undefined);
      return defaultWriter.toBytes(true);
    }
    return encodeCustom(data, cborEncoders, options);
  }

  // node_modules/cborg/lib/decode.js
  var defaultDecodeOptions = {
    strict: false,
    allowIndefinite: true,
    allowUndefined: true,
    allowBigInt: true
  };

  class Tokeniser {
    constructor(data, options = {}) {
      this._pos = 0;
      this.data = data;
      this.options = options;
    }
    pos() {
      return this._pos;
    }
    done() {
      return this._pos >= this.data.length;
    }
    next() {
      const byt = this.data[this._pos];
      let token = quick[byt];
      if (token === undefined) {
        const decoder = jump[byt];
        if (!decoder) {
          throw new Error(`${decodeErrPrefix} no decoder for major type ${byt >>> 5} (byte 0x${byt.toString(16).padStart(2, "0")})`);
        }
        const minor = byt & 31;
        token = decoder(this.data, this._pos, minor, this.options);
      }
      this._pos += token.encodedLength;
      return token;
    }
  }
  var DONE = Symbol.for("DONE");
  var BREAK = Symbol.for("BREAK");
  function tokenToArray(token, tokeniser, options) {
    const arr = [];
    for (let i = 0;i < token.value; i++) {
      const value = tokensToObject(tokeniser, options);
      if (value === BREAK) {
        if (token.value === Infinity) {
          break;
        }
        throw new Error(`${decodeErrPrefix} got unexpected break to lengthed array`);
      }
      if (value === DONE) {
        throw new Error(`${decodeErrPrefix} found array but not enough entries (got ${i}, expected ${token.value})`);
      }
      arr[i] = value;
    }
    return arr;
  }
  function tokenToMap(token, tokeniser, options) {
    const useMaps = options.useMaps === true;
    const rejectDuplicateMapKeys = options.rejectDuplicateMapKeys === true;
    const obj = useMaps ? undefined : {};
    const m = useMaps ? new Map : undefined;
    for (let i = 0;i < token.value; i++) {
      const key = tokensToObject(tokeniser, options);
      if (key === BREAK) {
        if (token.value === Infinity) {
          break;
        }
        throw new Error(`${decodeErrPrefix} got unexpected break to lengthed map`);
      }
      if (key === DONE) {
        throw new Error(`${decodeErrPrefix} found map but not enough entries (got ${i} [no key], expected ${token.value})`);
      }
      if (!useMaps && typeof key !== "string") {
        throw new Error(`${decodeErrPrefix} non-string keys not supported (got ${typeof key})`);
      }
      if (rejectDuplicateMapKeys) {
        if (useMaps && m.has(key) || !useMaps && Object.hasOwn(obj, key)) {
          throw new Error(`${decodeErrPrefix} found repeat map key "${key}"`);
        }
      }
      const value = tokensToObject(tokeniser, options);
      if (value === DONE) {
        throw new Error(`${decodeErrPrefix} found map but not enough entries (got ${i} [no value], expected ${token.value})`);
      }
      if (useMaps) {
        m.set(key, value);
      } else if (key === "__proto__") {
        Object.defineProperty(obj, key, { value, configurable: true, enumerable: true, writable: true });
      } else {
        obj[key] = value;
      }
    }
    return useMaps ? m : obj;
  }
  function* tokenToMapEntries(token, tokeniser, options) {
    for (let i = 0;i < token.value; i++) {
      const key = tokensToObject(tokeniser, options);
      if (key === BREAK) {
        if (token.value === Infinity) {
          break;
        }
        throw new Error(`${decodeErrPrefix} got unexpected break to lengthed map`);
      }
      if (key === DONE) {
        throw new Error(`${decodeErrPrefix} found map but not enough entries (got ${i} [no key], expected ${token.value})`);
      }
      const value = tokensToObject(tokeniser, options);
      if (value === DONE) {
        throw new Error(`${decodeErrPrefix} found map but not enough entries (got ${i} [no value], expected ${token.value})`);
      }
      yield [key, value];
    }
  }
  function createTagDecodeControl(tokeniser, options) {
    const decode = function() {
      if (decode._called) {
        throw new Error(`${decodeErrPrefix} tag decode() may only be called once`);
      }
      decode._called = true;
      const value = tokensToObject(tokeniser, options);
      if (value === DONE) {
        throw new Error(`${decodeErrPrefix} tag content missing`);
      }
      if (value === BREAK) {
        throw new Error(`${decodeErrPrefix} got unexpected break in tag content`);
      }
      return value;
    };
    decode.entries = function() {
      if (decode._called) {
        throw new Error(`${decodeErrPrefix} tag decode() may only be called once`);
      }
      decode._called = true;
      const token = tokeniser.next();
      if (!Type.equals(token.type, Type.map)) {
        throw new Error(`${decodeErrPrefix} entries() requires map content, got ${token.type.name}`);
      }
      const entries = [];
      for (const entry of tokenToMapEntries(token, tokeniser, options)) {
        entries.push(entry);
      }
      return entries;
    };
    decode._called = false;
    return decode;
  }
  function tokensToObject(tokeniser, options) {
    if (tokeniser.done()) {
      return DONE;
    }
    const token = tokeniser.next();
    if (Type.equals(token.type, Type.break)) {
      return BREAK;
    }
    if (token.type.terminal) {
      return token.value;
    }
    if (Type.equals(token.type, Type.array)) {
      return tokenToArray(token, tokeniser, options);
    }
    if (Type.equals(token.type, Type.map)) {
      return tokenToMap(token, tokeniser, options);
    }
    if (Type.equals(token.type, Type.tag)) {
      if (options.tags && typeof options.tags[token.value] === "function") {
        const decodeControl = createTagDecodeControl(tokeniser, options);
        const result = options.tags[token.value](decodeControl);
        if (!decodeControl._called) {
          throw new Error(`${decodeErrPrefix} tag decoder must call decode() or entries()`);
        }
        return result;
      }
      throw new Error(`${decodeErrPrefix} tag not supported (${token.value})`);
    }
    throw new Error("unsupported");
  }
  function decodeFirst(data, options) {
    if (!(data instanceof Uint8Array)) {
      throw new Error(`${decodeErrPrefix} data to decode must be a Uint8Array`);
    }
    options = Object.assign({}, defaultDecodeOptions, options);
    const u8aData = asU8A(data);
    const tokeniser = options.tokenizer || new Tokeniser(u8aData, options);
    const decoded = tokensToObject(tokeniser, options);
    if (decoded === DONE) {
      throw new Error(`${decodeErrPrefix} did not find any content to decode`);
    }
    if (decoded === BREAK) {
      throw new Error(`${decodeErrPrefix} got unexpected break`);
    }
    return [decoded, data.subarray(tokeniser.pos())];
  }
  function decode(data, options) {
    const [decoded, remainder] = decodeFirst(data, options);
    if (remainder.length > 0) {
      throw new Error(`${decodeErrPrefix} too many terminals, data makes no sense`);
    }
    return decoded;
  }

  // node_modules/cborg/lib/tagged.js
  class Tagged {
    constructor(tag, value) {
      if (typeof tag !== "number" || !Number.isInteger(tag) || tag < 0) {
        throw new TypeError("Tagged: tag must be a non-negative integer");
      }
      this.tag = tag;
      this.value = value;
    }
    static decoder(tag) {
      return (decode2) => new Tagged(tag, decode2());
    }
    static preserve(...tagNumbers) {
      const tags = {};
      for (const tag of tagNumbers) {
        tags[tag] = Tagged.decoder(tag);
      }
      return tags;
    }
  }
  Object.defineProperty(Tagged.prototype, Symbol.toStringTag, {
    value: "Tagged"
  });

  // src/witness.js
  var CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor";
  var CADENCE_EXTENSIONS = ["x-cadence-witness/v0", "cadence-witness/v0", "x-deal-cadence-v0"];
  var CADENCE_DEPTH = 16;
  var ED25519_SPKI_PREFIX = "302a300506032b6570032100";
  var enc = new TextEncoder;
  var canonicalCbor = (value) => encode(value, rfc8949EncodeOptions);
  var cborOptions = { allowIndefinite: false, coerceUndefinedToNull: false, useMaps: true };
  function hexToBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex))
      throw new Error("not hex");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0;i < out.length; i++)
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  var bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  function concat2(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
  function bytesEqual(a, b) {
    if (a.length !== b.length)
      return false;
    for (let i = 0;i < a.length; i++)
      if (a[i] !== b[i])
        return false;
    return true;
  }
  function b64Decode(s, urlSafe) {
    if (typeof s !== "string")
      throw new Error("not base64");
    let t = s.trim();
    if (urlSafe)
      t = t.replace(/-/g, "+").replace(/_/g, "/");
    t += "=".repeat((4 - t.length % 4) % 4);
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0;i < bin.length; i++)
      out[i] = bin.charCodeAt(i);
    return out;
  }
  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }
  async function ed25519Verify(key32, message, signature) {
    try {
      const key = await crypto.subtle.importKey("raw", key32, { name: "Ed25519" }, false, ["verify"]);
      return await crypto.subtle.verify("Ed25519", key, signature, message);
    } catch (e) {
      return false;
    }
  }
  var sigStructure = (protectedBstr, payload) => canonicalCbor(["Signature1", protectedBstr, new Uint8Array, payload]);
  function goRFC3339Nano(value) {
    const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(value);
    if (!m)
      throw new Error("issued_at is not RFC 3339");
    const fraction = (m[2] || "").padEnd(9, "0");
    const parsed = new Date(`${m[1]}.${fraction.slice(0, 3)}${m[3]}`);
    if (Number.isNaN(parsed.valueOf()))
      throw new Error("issued_at is not a time");
    const trimmed = fraction.replace(/0+$/, "");
    return `${parsed.toISOString().slice(0, 19)}${trimmed === "" ? "" : "." + trimmed}Z`;
  }
  function canonicalJson(value) {
    if (value === null || typeof value === "boolean")
      return String(value);
    if (typeof value === "string")
      return JSON.stringify(value);
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value))
        throw new Error("canonical JSON takes safe integers only");
      return String(value);
    }
    if (Array.isArray(value))
      return "[" + value.map(canonicalJson).join(",") + "]";
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  function decodePeaks(value) {
    if (!(value instanceof Uint8Array))
      return;
    const peaks = decode(value, { allowIndefinite: false, coerceUndefinedToNull: false });
    if (!Array.isArray(peaks) || peaks.some((p) => !(p instanceof Uint8Array) || p.length !== 32))
      return;
    if (!bytesEqual(canonicalCbor(peaks), value))
      return;
    return peaks;
  }
  async function verifyCheckpoint(cose, mmr) {
    const fail = (reason) => ({ ok: false, reason });
    try {
      if (!(cose instanceof Uint8Array) || cose.length < 2 || cose[0] !== 210 || cose[1] !== 132)
        return fail("not a tagged COSE_Sign1");
      const items = decode(cose.subarray(1), cborOptions);
      if (!Array.isArray(items) || items.length !== 4 || !(items[0] instanceof Uint8Array) || !(items[1] instanceof Map) || items[1].size !== 0 || !(items[2] instanceof Uint8Array) || !(items[3] instanceof Uint8Array))
        return fail("malformed COSE_Sign1");
      if (!bytesEqual(concat2(Uint8Array.of(210), canonicalCbor(items)), cose))
        return fail("not canonical CBOR");
      const headers = decode(items[0], cborOptions);
      if (!(headers instanceof Map))
        return fail("malformed protected header");
      const kid = headers.get(4);
      const cwt = headers.get(15);
      if (headers.size !== 4 || headers.get(1) !== -8 || headers.get(3) !== CHECKPOINT_CONTENT_TYPE || !(kid instanceof Uint8Array) || kid.length !== 32 || !(cwt instanceof Map) || cwt.size !== 2)
        return fail("not the checkpoint profile's protected header");
      const logId = cwt.get(1);
      const subject = cwt.get(2);
      if (typeof logId !== "string" || typeof subject !== "string")
        return fail("malformed CWT claims");
      const claims = decode(items[2], cborOptions);
      if (!(claims instanceof Map) || !bytesEqual(canonicalCbor(claims), items[2]))
        return fail("claims are not canonical CBOR");
      const allowed = new Set(["kind", "log_size", "commitment", "prev_size", "prev_commitment", "issued_at", "cadence", "consistency_proof"]);
      if (claims.size < 6 || [...claims.keys()].some((k) => typeof k !== "string" || !allowed.has(k)) || claims.get("kind") !== "cll-checkpoint")
        return fail("not a CLL checkpoint");
      const size = claims.get("log_size");
      const prevSize = claims.get("prev_size");
      const issuedAt = claims.get("issued_at");
      if (!Number.isSafeInteger(size) || size < 1 || !Number.isSafeInteger(prevSize) || prevSize < 0 || prevSize >= size || typeof issuedAt !== "string")
        return fail("malformed sizes or time");
      if (subject !== `${logId}#${size}`)
        return fail("CWT subject does not name this log and size");
      const peaks = decodePeaks(claims.get("commitment"));
      if (!peaks || peaks.length !== mmr.peaks(size).length)
        return fail("malformed commitment");
      const prevCommitment = claims.get("prev_commitment");
      if (!(prevCommitment instanceof Uint8Array))
        return fail("malformed previous commitment");
      let prevPeaks = [];
      if (prevSize === 0) {
        if (prevCommitment.length !== 0 || claims.has("consistency_proof"))
          return fail("a first checkpoint carries no previous commitment");
      } else {
        prevPeaks = decodePeaks(prevCommitment);
        const proof = claims.get("consistency_proof");
        if (!prevPeaks || !(proof instanceof Map))
          return fail("missing consistency proof");
        const wire = {
          v: 1,
          kind: "consistency",
          size_a: proof.get("size_a"),
          size_b: proof.get("size_b"),
          old_peaks: (proof.get("old_peaks") || []).map(bytesToHex),
          witness: (proof.get("witness") || []).map((w) => Array.isArray(w) ? w.map(bytesToHex) : w),
          new_peaks: (proof.get("new_peaks") || []).map(bytesToHex)
        };
        const oldRoot = bytesToHex(await mmr.rootFromPeaks(prevPeaks));
        const newRoot = bytesToHex(await mmr.rootFromPeaks(peaks));
        if (proof.size !== 5 || wire.size_a !== prevSize || wire.size_b !== size || !await mmr.verifyConsistency(oldRoot, prevSize, newRoot, size, wire))
          return fail("the checkpoint does not extend its previous one");
      }
      if (!await ed25519Verify(kid, sigStructure(items[0], items[2]), items[3]))
        return fail("signature does not verify under the key the checkpoint names");
      return {
        ok: true,
        logId,
        size,
        peaks,
        prevSize,
        prevPeaks,
        issuedAt,
        kid: bytesToHex(kid),
        root: bytesToHex(await mmr.rootFromPeaks(peaks)),
        prevRoot: prevSize === 0 ? "" : bytesToHex(await mmr.rootFromPeaks(prevPeaks))
      };
    } catch (e) {
      return fail("malformed: " + (e && e.message ? e.message : e));
    }
  }
  async function checkpointEntryHash(cp) {
    const projection = {
      v: 1,
      kind: "mmr_checkpoint",
      log_id: cp.logId,
      mmr_size: cp.size,
      root: cp.root,
      prev_size: cp.prevSize,
      prev_root: cp.prevRoot,
      key_id: cp.kid,
      timestamp: goRFC3339Nano(cp.issuedAt)
    };
    return sha256(await sha256(enc.encode(canonicalJson(projection))));
  }
  function largestPowerBelow(n) {
    let p = 1;
    while (p * 2 < n)
      p *= 2;
    return p;
  }
  function expectedPath(size, index) {
    let count = 0, nodes = size, position = index;
    while (nodes > 1) {
      count++;
      const split = largestPowerBelow(nodes);
      if (position < split)
        nodes = split;
      else {
        nodes -= split;
        position -= split;
      }
    }
    return count;
  }
  async function receiptRoot(entry, index, size, path) {
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size || path.length !== expectedPath(size, index))
      return;
    const siblings = [...path];
    const leaf = await sha256(concat2(Uint8Array.of(0), entry));
    const fold = async (nodes, position) => {
      if (nodes === 1)
        return leaf;
      const sibling = siblings.pop();
      if (sibling === undefined)
        return;
      const split = largestPowerBelow(nodes);
      if (position < split) {
        const child2 = await fold(split, position);
        return child2 === undefined ? undefined : sha256(concat2(Uint8Array.of(1), child2, sibling));
      }
      const child = await fold(nodes - split, position - split);
      return child === undefined ? undefined : sha256(concat2(Uint8Array.of(1), sibling, child));
    };
    const root = await fold(size, index);
    return root !== undefined && siblings.length === 0 ? root : undefined;
  }
  async function verifyReceipt(entry, receiptBytes, leafIndex, treeSize, key32) {
    try {
      if (receiptBytes.length < 2 || receiptBytes[0] !== 210)
        return false;
      const items = decode(receiptBytes.subarray(1), cborOptions);
      if (!Array.isArray(items) || items.length !== 4 || !(items[0] instanceof Uint8Array) || !(items[1] instanceof Map) || !(items[3] instanceof Uint8Array))
        return false;
      const headers = decode(items[0], cborOptions);
      if (!(headers instanceof Map) || headers.get(1) !== -8 || headers.get(395) !== 1)
        return false;
      const vdp = items[1].get(396);
      if (!(vdp instanceof Map))
        return false;
      const proofs = vdp.get(-1);
      if (!Array.isArray(proofs) || proofs.length !== 1 || !(proofs[0] instanceof Uint8Array))
        return false;
      const proof = decode(proofs[0], { allowIndefinite: false });
      if (!Array.isArray(proof) || proof.length !== 3 || proof[0] !== treeSize || proof[1] !== leafIndex || !Array.isArray(proof[2]) || proof[2].some((h) => !(h instanceof Uint8Array) || h.length !== 32))
        return false;
      const root = await receiptRoot(entry, leafIndex, treeSize, proof[2]);
      if (!root)
        return false;
      return ed25519Verify(key32, sigStructure(items[0], root), items[3]);
    } catch (e) {
      return false;
    }
  }
  function parseWitnessList(text) {
    const doc = JSON.parse(text);
    const rows = Array.isArray(doc) ? doc : doc && Array.isArray(doc.witnesses) ? doc.witnesses : null;
    if (!rows)
      throw new Error('a witness list is {"witnesses": [...]} or an array of rows');
    return rows.filter((r) => r && typeof r === "object");
  }
  function witnessBinding(url) {
    const i = url.indexOf("://");
    if (i < 0)
      return "cll";
    const scheme = url.slice(0, i).toLowerCase();
    for (const b of ["rekor", "scrapi"])
      if (scheme.startsWith(b + "+"))
        return b;
    return "cll";
  }
  function witnessEndpoint(url) {
    let u = url;
    if (witnessBinding(u) !== "cll")
      u = u.slice(u.indexOf("+") + 1);
    return u.replace(/\/+$/, "");
  }
  async function rowKeys(row) {
    const byHash = new Map;
    for (const b64 of Array.isArray(row.public_keys) ? row.public_keys : []) {
      try {
        const der = b64Decode(b64, false);
        if (der.length === 44 && bytesToHex(der.subarray(0, 12)) === ED25519_SPKI_PREFIX)
          byHash.set(bytesToHex(await sha256(der)), der.subarray(12));
      } catch (e) {}
    }
    const keys = [];
    for (const id of Array.isArray(row.key_ids) ? row.key_ids : []) {
      if (byHash.has(id))
        keys.push(byHash.get(id));
      else if (typeof id === "string" && /^[0-9a-f]{64}$/.test(id))
        keys.push(hexToBytes(id));
    }
    return keys;
  }
  var asInt = (v) => typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  async function checkReceipts(cp, entries, list) {
    const out = [];
    const entry = await checkpointEntryHash(cp);
    for (const e of entries || []) {
      const url = e && typeof e.ts_url === "string" ? e.ts_url : "";
      const r = { witness: url, status: "withheld", reason: "" };
      out.push(r);
      try {
        if (bytesToHex(entry) !== e.entry_hash) {
          r.status = "fail";
          r.reason = "the receipt is for a different checkpoint";
          continue;
        }
        if (!list) {
          r.reason = "present, not checked: choose a witness list to check it";
          continue;
        }
        const binding = witnessBinding(url), endpoint = witnessEndpoint(url);
        const row = list.find((w) => (w.binding || "cll") === binding && typeof w.endpoint === "string" && w.endpoint.replace(/\/+$/, "") === endpoint);
        if (!row) {
          r.reason = "present, not checked: your witness list has no entry for this witness";
          continue;
        }
        if (binding !== "cll") {
          r.reason = "present, not checked: this page checks cll receipts only, not " + binding;
          continue;
        }
        const keys = await rowKeys(row);
        if (!keys.length) {
          r.reason = "present, not checked: your witness list names no usable key for this witness";
          continue;
        }
        const bytes = b64Decode(e.receipt_b64, false);
        let ok = false;
        for (const key of keys)
          if (await verifyReceipt(entry, bytes, asInt(e.leaf_index), asInt(e.tree_size), key))
            ok = true;
        r.status = ok ? "pass" : "fail";
        r.reason = ok ? "verified under " + (row.name || endpoint) + "'s key from your witness list" : "does not verify under the key your witness list names";
      } catch (err) {
        r.status = "fail";
        r.reason = "malformed receipt";
      }
    }
    return out;
  }
  function overall(receipts) {
    if (receipts.some((r) => r.status === "fail"))
      return "fail";
    if (receipts.some((r) => r.status === "pass"))
      return "pass";
    return "withheld";
  }
  async function cadenceLeaf(logId, size, checkpointSha256, salt) {
    const body = canonicalJson({ checkpoint_sha256: checkpointSha256, log_id: logId, salt, size });
    return sha256(concat2(Uint8Array.of(0), enc.encode(body)));
  }
  async function checkWitnessEvidence(bundle, mmr, list) {
    const out = { checkpoint: { status: "withheld", reason: "the bundle carries no signed checkpoint" }, rung: null, chain: null, receipts: [], status: "absent" };
    const stated = bundle && bundle.checkpoint;
    if (!stated || typeof stated.cose !== "string")
      return out;
    let cose;
    try {
      cose = b64Decode(stated.cose, true);
    } catch (e) {
      out.checkpoint = { status: "fail", reason: "the signed checkpoint is not base64url" };
      out.status = "fail";
      return out;
    }
    const cp = await verifyCheckpoint(cose, mmr);
    if (!cp.ok) {
      out.checkpoint = { status: "fail", reason: cp.reason };
      out.status = "fail";
      return out;
    }
    const mismatch = ["log_id", "mmr_size", "root"].find((k) => stated[k] !== undefined && String(stated[k]) !== String({ log_id: cp.logId, mmr_size: cp.size, root: cp.root }[k]));
    if (mismatch) {
      out.checkpoint = { status: "fail", reason: "the bundle's copy of " + mismatch + " differs from the signed checkpoint" };
      out.status = "fail";
      return out;
    }
    out.checkpoint = { status: "pass", reason: "signature verifies under the key the checkpoint names", logId: cp.logId, size: cp.size, kid: cp.kid };
    const exts = bundle.extensions || {};
    const name = CADENCE_EXTENSIONS.find((n) => exts[n] && typeof exts[n] === "object");
    const chain = name ? exts[name] : null;
    if (chain && chain.state === "witnessed")
      return checkCadence(out, chain, cp, cose, mmr, list);
    const direct = Array.isArray(stated.witnesses) ? stated.witnesses : [];
    if (!direct.length)
      return out;
    out.receipts = await checkReceipts(cp, direct, list);
    out.status = overall(out.receipts);
    if (out.status === "pass")
      out.rung = "witnessed";
    return out;
  }
  async function checkCadence(out, chain, cp, cose, mmr, list) {
    const failChain = (reason) => {
      out.chain = { status: "fail", reason };
      out.status = "fail";
      return out;
    };
    let leafCp = cp, leafCose = cose;
    if (chain.extent === "part") {
      const earlier = chain.earlier || {};
      let prior;
      try {
        leafCose = b64Decode((earlier.checkpoint || {}).cose, true);
        prior = await verifyCheckpoint(leafCose, mmr);
      } catch (e) {
        return failChain("the earlier checkpoint is malformed");
      }
      if (!prior.ok)
        return failChain("the earlier checkpoint does not verify: " + prior.reason);
      if (prior.kid !== cp.kid || prior.logId !== cp.logId || prior.size >= cp.size)
        return failChain("the earlier checkpoint is not an earlier checkpoint of this log, signed by the same key");
      const p = earlier.consistency_proof || {};
      const wire = { v: p.v, kind: p.kind, size_a: asInt(p.old_size), size_b: asInt(p.new_size), old_peaks: p.old_peaks, witness: p.witness, new_peaks: p.new_peaks };
      if (!await mmr.verifyConsistency(prior.root, prior.size, cp.root, cp.size, wire))
        return failChain("the bundle's checkpoint does not extend the earlier one");
      leafCp = prior;
    }
    const size = asInt(chain.size), index = asInt(chain.index);
    const logId = chain.log_id !== undefined ? chain.log_id : chain.deal_log_id;
    if (logId !== leafCp.logId || size !== leafCp.size)
      return failChain("the chain does not name this checkpoint");
    if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** CADENCE_DEPTH || typeof chain.salt !== "string" || !chain.salt || !Array.isArray(chain.path) || chain.path.length !== CADENCE_DEPTH)
      return failChain("the chain is malformed");
    let node = await cadenceLeaf(logId, size, bytesToHex(await sha256(leafCose)), chain.salt);
    for (let level = 0;level < CADENCE_DEPTH; level++) {
      const sib = hexToBytes(chain.path[level]);
      if (sib.length !== 32)
        return failChain("the chain is malformed");
      node = index >> level & 1 ? await sha256(concat2(Uint8Array.of(1), sib, node)) : await sha256(concat2(Uint8Array.of(1), node, sib));
    }
    const inner = chain.cadence || {};
    let cadenceCose, cadence;
    try {
      cadenceCose = b64Decode((inner.checkpoint || {}).cose, true);
      cadence = await verifyCheckpoint(cadenceCose, mmr);
    } catch (e) {
      return failChain("the cadence checkpoint is malformed");
    }
    if (!cadence.ok)
      return failChain("the cadence checkpoint does not verify: " + cadence.reason);
    if (cadence.kid !== cp.kid)
      return failChain("the cadence checkpoint is signed by a different key");
    if (inner.log_id !== cadence.logId)
      return failChain("the cadence log id does not match its checkpoint");
    const proof = inner.inclusion_proof || {};
    if (!await mmr.verifyInclusion(cadence.root, cadence.size, asInt(inner.entry_index), bytesToHex(node), { ...proof, size: asInt(proof.size), leaf_index: asInt(proof.leaf_index) }))
      return failChain("the cadence entry is not included in the cadence checkpoint");
    out.chain = { status: "pass", reason: "the checkpoint is a leaf of a cadence entry included in the cadence checkpoint" };
    out.receipts = await checkReceipts(cadence, inner.witnesses, list);
    out.status = out.receipts.length ? overall(out.receipts) : "withheld";
    if (out.status === "pass") {
      out.rung = chain.extent === "part" ? "witnessed_in_part" : "witnessed";
      if (chain.extent === "part") {
        out.stepsWitnessed = mmr.leafCountFromSize(leafCp.size);
        out.steps = mmr.leafCountFromSize(cp.size);
      }
    }
    return out;
  }

  // src/witness-check.js
  globalThis.WitnessCheck = Object.freeze({ checkWitnessEvidence, parseWitnessList });
})();
