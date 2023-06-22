import CryptoJS from 'crypto-js';
import bigInt, { BigInteger } from 'big-integer';

class HashUtils {
  private static INFO_BITS: CryptoJS.lib.WordArray = CryptoJS.enc.Utf8.parse('Caldera Derived Key');

  public static HashSha256(buf: CryptoJS.lib.WordArray): string {
    const a: string = CryptoJS.SHA256(buf).toString(CryptoJS.enc.Hex);
    return a.padStart(64, '0');
  }

  public static HexHash(hexString: string): string {
    return this.HashSha256(CryptoJS.enc.Hex.parse(hexString));
  }

  public static HexToLong(hexString: string): BigInteger {
    return bigInt(hexString, 16);
  }

  public static LongToHex(longValue: BigInteger): string {
    return longValue.toString(16);
  }

  public static GetRandom(size: number): BigInteger {
    const randomBytes = CryptoJS.lib.WordArray.random(size);
    const randomHex = CryptoJS.enc.Hex.stringify(randomBytes);
    return this.HexToLong(randomHex);
  }

  public static PadHex(hex: string | BigInteger): string {
    let hashStr = '';

    if (hex instanceof bigInt) hashStr = this.LongToHex(hex);
    else if (typeof hex === 'string') hashStr = hex;

    if (hashStr.length % 2 === 1) hashStr = `0${hashStr}`;
    else if ('89ABCDEFabcdef'.includes(hashStr[0])) hashStr = `00${hashStr}`;

    return hashStr;
  }

  public static ComputeHdkf(ikm: CryptoJS.lib.WordArray, salt: CryptoJS.lib.WordArray): CryptoJS.lib.WordArray {
    const prk = CryptoJS.HmacSHA256(ikm, salt);

    const updateByteArray = [1];
    const updateWordArray = this.ByteArrayToWordArray(updateByteArray);
    const infoBitsUpdate = this.INFO_BITS.concat(updateWordArray);

    const hash = CryptoJS.HmacSHA256(infoBitsUpdate, prk);
    hash.sigBytes = 16;
    hash.clamp();

    return hash;
  }

  public static CalculateU(bigA: BigInteger, bigB: BigInteger) {
    const uHexHash = this.HexHash(this.PadHex(bigA) + this.PadHex(bigB));
    return this.HexToLong(uHexHash);
  }

  private static ByteArrayToWordArray(ba: number[]): CryptoJS.lib.WordArray {
    const wa: number[] = [];
    let i: number;

    for (i = 0; i < ba.length; i++) {
      wa[(i / 4) | 0] |= ba[i] << (24 - 8 * i);
    }

    return CryptoJS.lib.WordArray.create(wa, ba.length);
  }

  private static WordToByteArray(word: number, length: number): number[] {
    const ba: number[] = [];
    const xFF: number = 0xff;

    if (length > 0) ba.push(word >>> 24);
    if (length > 1) ba.push((word >>> 16) & xFF);
    if (length > 2) ba.push((word >>> 8) & xFF);
    if (length > 3) ba.push(word & xFF);

    return ba;
  }

  private static WordArrayToByteArray(wordArray: any, length: any) {
    if (wordArray.hasOwnProperty('sigBytes') && wordArray.hasOwnProperty('words')) {
      length = wordArray.sigBytes;
      wordArray = wordArray.words;
    }

    const result: any[] = [];
    let bytes: number[] = [];
    let i: number = 0;
    while (length > 0) {
      bytes = this.WordToByteArray(wordArray[i], Math.min(4, length));
      length -= bytes.length;
      result.push(bytes);
      i++;
    }
    return [].concat.apply([], result);
  }
}

export { HashUtils };
