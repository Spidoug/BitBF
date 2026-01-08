// ========================== UTILS / CRYPTO ==========================

/**
 * Validates the format of a WIF (Wallet Import Format) string.
 */
boolean looksLikeWIF(String s) {
  s = sanitize(s);
  if (!(s.length() == 51 || s.length() == 52)) return false;
  char c0 = s.charAt(0);
  // Mainnet: 5, K, L | Testnet: 9, c
  return (c0 == '5' || c0 == 'K' || c0 == 'L' || c0 == '9' || c0 == 'c');
}

/**
 * Validates address length and prefix.
 * Note: Actual validation happens during decodeSegwitAddress or base58DecodeChecked.
 */
boolean looksLikeAddress(String s) {
  s = sanitize(s).toLowerCase();
  if (s.startsWith("bc1")) {
    return s.length() >= 14 && s.length() <= 90;
  }
  if (s.length() >= 26 && s.length() <= 35) {
    char c0 = s.charAt(0);
    return (c0 == '1' || c0 == '3' || c0 == 'm' || c0 == 'n');
  }
  return false;
}

String sanitize(String s) {
  if (s == null) return "";
  return s.trim().replaceAll("[\\p{Z}\\s]", "");
}

// --- Clipboard Helpers ---

String pasteFromClipboard() {
  try {
    Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
    Object data = cb.getData(DataFlavor.stringFlavor);
    return (data == null) ? "" : data.toString();
  } catch (Exception e) { return ""; }
}

void copyToClipboard(String s) {
  try {
    java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(s);
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
  } catch(Exception e) {}
}

// --- Hashing Functions ---

byte[] sha256(byte[] data) {
  try {
    return MessageDigest.getInstance("SHA-256").digest(data);
  } catch (Exception e) { throw new RuntimeException(e); }
}

byte[] doubleSHA256(byte[] data) {
  return sha256(sha256(data));
}

byte[] ripemd160(byte[] data) {
  return RIPEMD160.digest(data);
}

byte[] hash160(byte[] data) {
  return ripemd160(sha256(data));
}

// --- Formatting ---

String toHex(byte[] b) {
  StringBuilder sb = new StringBuilder();
  for (byte value : b) sb.append(hex2(value & 0xFF));
  return sb.toString();
}

String hex2(int v) {
  String h = Integer.toHexString(v).toUpperCase();
  return (h.length() == 1) ? ("0" + h) : h;
}

// ========================== BASE58 (Checked) ==========================

/**
 * Decodes a Base58Check string and validates the 4-byte checksum.
 * Prevents false positives in Legacy and P2SH addresses.
 */
byte[] base58DecodeChecked(String s) {
  byte[] decoded = base58Decode(s);
  if (decoded.length < 4) return null;

  byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
  byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
  byte[] actualChecksum = Arrays.copyOfRange(doubleSHA256(data), 0, 4);

  if (!Arrays.equals(checksum, actualChecksum)) return null; 
  return data; // Returns [version + payload]
}

byte[] base58Decode(String s) {
  s = sanitize(s);
  if (s.length() == 0) return new byte[0];

  BigInteger num = BigInteger.ZERO;
  for (int i = 0; i < s.length(); i++) {
    int p = B58.indexOf(s.charAt(i));
    if (p < 0) throw new RuntimeException("Invalid Base58 character: " + s.charAt(i));
    num = num.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(p));
  }

  byte[] temp = num.toByteArray();
  int srcPos = (temp.length > 1 && temp[0] == 0) ? 1 : 0;
  int len = temp.length - srcPos;

  int count1 = 0;
  while (count1 < s.length() && s.charAt(count1) == '1') count1++;

  byte[] out = new byte[count1 + len];
  System.arraycopy(temp, srcPos, out, count1, len);
  return out;
}

String base58Encode(byte[] input) {
  if (input.length == 0) return "";
  BigInteger num = new BigInteger(1, input);
  StringBuilder sb = new StringBuilder();
  while (num.compareTo(BigInteger.ZERO) > 0) {
    BigInteger[] dr = num.divideAndRemainder(BigInteger.valueOf(58));
    sb.append(B58.charAt(dr[1].intValue()));
    num = dr[0];
  }
  for (int i = 0; i < input.length && input[i] == 0; i++) sb.append('1');
  return sb.reverse().toString();
}

String base58CheckEncode(byte version, byte[] payload) {
  byte[] data = new byte[1 + payload.length];
  data[0] = version;
  System.arraycopy(payload, 0, data, 1, payload.length);
  byte[] checksum = Arrays.copyOfRange(doubleSHA256(data), 0, 4);
  byte[] full = new byte[data.length + 4];
  System.arraycopy(data, 0, full, 0, data.length);
  System.arraycopy(checksum, 0, full, data.length, 4);
  return base58Encode(full);
}

String base58CheckEncodeWithCompression(byte version, byte[] payload, boolean compressed) {
  byte[] data = new byte[compressed ? 34 : 33];
  data[0] = version;
  System.arraycopy(payload, 0, data, 1, 32);
  if (compressed) data[33] = 0x01;
  byte[] checksum = Arrays.copyOfRange(doubleSHA256(data), 0, 4);
  byte[] full = new byte[data.length + 4];
  System.arraycopy(data, 0, full, 0, data.length);
  System.arraycopy(checksum, 0, full, data.length, 4);
  return base58Encode(full);
}

void saveMatch(String wif, String pub, String target, String type) {
  try {
    String filename = sketchPath("Found_matches.txt");
    FileWriter fw = new FileWriter(filename, true);
    BufferedWriter bw = new BufferedWriter(fw);
    PrintWriter out = new PrintWriter(bw);

    out.println("====================================================");
    out.println("TIMESTAMP: " + nf(day(), 2) + "/" + nf(month(), 2) + "/" + year() + " " + nf(hour(), 2) + ":" + nf(minute(), 2) + ":" + nf(second(), 2));
    out.println("TYPE:      " + type);
    out.println("WIF PRIV:  " + wif);
    out.println("PUB HEX:   " + pub);
    out.println("ADDRESS:   " + target);
    out.println("====================================================");
    out.println();

    out.close();
    bw.close();
    fw.close();
  }
  catch (Exception e) {
    statusMsg = "File write error: " + e.getMessage();
  }
}

// ========================== SECP256K1 ==========================
static class Secp256k1 {
  static final BigInteger P  = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  static final BigInteger N  = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  static final BigInteger GX = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
  static final BigInteger GY = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

  static class Point {
    BigInteger x, y;
    boolean inf;
    Point(BigInteger x, BigInteger y) {
      this.x = x;
      this.y = y;
      this.inf = false;
    }
    Point() {
      this.inf = true;
    }
  }

  static Point G() {
    return new Point(GX, GY);
  }

  static BigInteger mod(BigInteger a) {
    a = a.mod(P);
    return (a.signum() < 0) ? a.add(P) : a;
  }

  static BigInteger inv(BigInteger a) {
    return a.modPow(P.subtract(BigInteger.valueOf(2)), P);
  }

  static Point add(Point p, Point q) {
    if (p.inf) return q;
    if (q.inf) return p;
    if (p.x.equals(q.x)) {
      if (p.y.equals(q.y)) return dbl(p);
      return new Point();
    }
    BigInteger lambda = mod(q.y.subtract(p.y)).multiply(inv(mod(q.x.subtract(p.x)))).mod(P);
    BigInteger xr = mod(lambda.multiply(lambda).subtract(p.x).subtract(q.x));
    BigInteger yr = mod(lambda.multiply(p.x.subtract(xr)).subtract(p.y));
    return new Point(xr, yr);
  }

  static Point dbl(Point p) {
    if (p.inf || p.y.signum() == 0) return new Point();
    BigInteger lambda = mod(p.x.multiply(p.x).multiply(BigInteger.valueOf(3)))
      .multiply(inv(mod(p.y.multiply(BigInteger.valueOf(2))))).mod(P);
    BigInteger xr = mod(lambda.multiply(lambda).subtract(p.x.shiftLeft(1)));
    BigInteger yr = mod(lambda.multiply(p.x.subtract(xr)).subtract(p.y));
    return new Point(xr, yr);
  }

  static Point mul(BigInteger k, Point p) {
    k = k.mod(N);
    Point r = new Point();
    Point addend = p;
    for (int i = k.bitLength() - 1; i >= 0; i--) {
      r = dbl(r);
      if (k.testBit(i)) r = add(r, addend);
    }
    return r;
  }

  static byte[] publicKeyFromPrivate(BigInteger d, boolean compressed) {
    if (d.signum() <= 0 || d.compareTo(N) >= 0) throw new RuntimeException("Privkey out of range.");
    Point Q = mul(d, G());
    if (Q.inf) throw new RuntimeException("Point at infinity.");

    byte[] xb = toFixed32(Q.x);
    if (!compressed) {
      byte[] yb = toFixed32(Q.y);
      byte[] out = new byte[65];
      out[0] = 0x04;
      System.arraycopy(xb, 0, out, 1, 32);
      System.arraycopy(yb, 0, out, 33, 32);
      return out;
    } else {
      byte[] out = new byte[33];
      out[0] = (byte)(Q.y.testBit(0) ? 0x03 : 0x02);
      System.arraycopy(xb, 0, out, 1, 32);
      return out;
    }
  }

  static byte[] toFixed32(BigInteger v) {
    byte[] b = v.toByteArray();
    if (b.length == 32) return b;
    byte[] out = new byte[32];
    if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
    else System.arraycopy(b, 0, out, 32 - b.length, b.length);
    return out;
  }
}

// ========================== BECH32 ==========================
// ========================== BECH32 (BIP-173 + BIP-350) ==========================
static class Bech32 {
  private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

  // Checksum constants for BIP-173 (Bech32) and BIP-350 (Bech32m)
  private static final int BECH32_CONST  = 1;
  private static final int BECH32M_CONST = 0x2bc830a3;

  static class DecodeResult {
    String hrp;      // "bc" / "tb"
    byte[] data;     // 5-bit values WITHOUT checksum, includes witness version at data[0]
    int encoding;    // 0 = bech32, 1 = bech32m
    DecodeResult(String hrp, byte[] data, int encoding) {
      this.hrp = hrp;
      this.data = data;
      this.encoding = encoding;
    }
  }

  /**
   * ✅ Correct SegWit decode:
   * - rejects mixed-case
   * - validates checksum (bech32 or bech32m)
   * - validates HRP (bc/tb) and witness version
   * - validates witness program length
   * - converts 5-bit to 8-bit with strict (no padding)
   *
   * Returns witness program bytes (20 for P2WPKH, 32 for P2WSH, etc.)
   */
  static byte[] decodeSegwitAddress(String addr) {
    DecodeResult dr = decode(addr);
    if (dr == null) return null;

    // HRP check
    if (!(dr.hrp.equals("bc") || dr.hrp.equals("tb"))) return null;

    if (dr.data == null || dr.data.length < 1) return null;

    int witver = dr.data[0] & 0xFF;
    if (witver > 16) return null;

    // BIP-350 rule:
    // witver == 0 -> must be BECH32
    // witver >= 1 -> must be BECH32M
    if (witver == 0 && dr.encoding != 0) return null;
    if (witver >= 1 && dr.encoding != 1) return null;

    // Convert from 5-bit to 8-bit and remove witness version
    // ✅ this is the "fixed" version of your line
    byte[] prog = convertBits(Arrays.copyOfRange(dr.data, 1, dr.data.length), 5, 8, false);
    if (prog == null) return null;

    // Witness program length rules
    if (prog.length < 2 || prog.length > 40) return null;
    if (witver == 0 && !(prog.length == 20 || prog.length == 32)) return null; // v0 rules

    return prog;
  }

  /**
   * Full bech32/bech32m decode. Returns payload data WITHOUT checksum.
   */
  static DecodeResult decode(String str) {
    if (str == null) return null;
    str = str.trim();
    if (str.length() < 8 || str.length() > 90) return null;

    // Reject invalid range and mixed-case
    boolean hasLower = false, hasUpper = false;
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (c < 33 || c > 126) return null;
      if (Character.isLowerCase(c)) hasLower = true;
      if (Character.isUpperCase(c)) hasUpper = true;
    }
    if (hasLower && hasUpper) return null;

    str = str.toLowerCase();

    int pos = str.lastIndexOf('1');
    // HRP must be at least 1 char; need at least 6 checksum chars after separator
    if (pos < 1 || pos + 7 > str.length()) return null;

    String hrp = str.substring(0, pos);
    int dataLen = str.length() - pos - 1;
    if (dataLen < 6) return null;

    byte[] values = new byte[dataLen];
    for (int i = 0; i < dataLen; i++) {
      int v = CHARSET.indexOf(str.charAt(pos + 1 + i));
      if (v < 0) return null;
      values[i] = (byte) v;
    }

    int pm = polymod(concat(hrpExpand(hrp), values));
    int encoding = -1;
    if (pm == BECH32_CONST) encoding = 0;
    else if (pm == BECH32M_CONST) encoding = 1;
    else return null;

    // Strip 6 checksum bytes
    byte[] actualData = Arrays.copyOfRange(values, 0, values.length - 6);

    return new DecodeResult(hrp, actualData, encoding);
  }

  // ---------------- internals ----------------

  static String encodeSegwitAddress(String hrp, int witver, byte[] witprog) {
    if (hrp == null) throw new RuntimeException("HRP null");
    hrp = hrp.toLowerCase();

    if (witver < 0 || witver > 16) throw new RuntimeException("Invalid witness version");
    if (witprog == null || witprog.length < 2 || witprog.length > 40) throw new RuntimeException("Invalid witness program length");
    if (witver == 0 && !(witprog.length == 20 || witprog.length == 32)) throw new RuntimeException("Invalid v0 program length");

    byte[] data5 = convertBits(witprog, 8, 5, true);
    byte[] combined = new byte[1 + data5.length];
    combined[0] = (byte) witver;
    System.arraycopy(data5, 0, combined, 1, data5.length);

    int constant = (witver == 0) ? BECH32_CONST : BECH32M_CONST;
    return encode(hrp, combined, constant);
  }

  private static String encode(String hrp, byte[] data, int constant) {
    byte[] checksum = createChecksum(hrp, data, constant);
    byte[] combined = concat(data, checksum);
    StringBuilder sb = new StringBuilder(hrp).append('1');
    for (byte b : combined) sb.append(CHARSET.charAt(b & 0xFF));
    return sb.toString();
  }

  private static byte[] createChecksum(String hrp, byte[] data, int constant) {
    byte[] expanded = hrpExpand(hrp);
    byte[] enc = new byte[data.length + 6];
    System.arraycopy(data, 0, enc, 0, data.length);
    int mod = polymod(concat(expanded, enc)) ^ constant;
    byte[] ret = new byte[6];
    for (int i = 0; i < 6; i++) ret[i] = (byte) ((mod >>> (5 * (5 - i))) & 31);
    return ret;
  }

  private static int polymod(byte[] values) {
    int chk = 1;
    for (byte v : values) {
      int b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ (v & 0xff);
      for (int i = 0; i < 5; i++) if (((b >>> i) & 1) == 1) chk ^= GENERATOR[i];
    }
    return chk;
  }

  private static byte[] hrpExpand(String hrp) {
    byte[] ret = new byte[hrp.length() * 2 + 1];
    for (int i = 0; i < hrp.length(); i++) ret[i] = (byte) (hrp.charAt(i) >> 5);
    ret[hrp.length()] = 0;
    for (int i = 0; i < hrp.length(); i++) ret[hrp.length() + 1 + i] = (byte) (hrp.charAt(i) & 31);
    return ret;
  }

  // Strict convertbits (BIP-173 reference behavior)
  private static byte[] convertBits(byte[] data, int from, int to, boolean pad) {
    int acc = 0, bits = 0;
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    int maxv = (1 << to) - 1;

    for (byte value : data) {
      int b = value & 0xff;
      // for 5-bit input, values must be < 32
      if ((b >> from) != 0) return null;

      acc = (acc << from) | b;
      bits += from;
      while (bits >= to) {
        bits -= to;
        out.write((acc >>> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) out.write((acc << (to - bits)) & maxv);
    } else {
      if (bits >= from) return null;
      if (((acc << (to - bits)) & maxv) != 0) return null;
    }

    return out.toByteArray();
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] ret = new byte[a.length + b.length];
    System.arraycopy(a, 0, ret, 0, a.length);
    System.arraycopy(b, 0, ret, a.length, b.length);
    return ret;
  }
}

// ========================== RIPEMD160 ==========================
static class RIPEMD160 {
  static byte[] digest(byte[] msg) {
    int[] h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    byte[] padded = pad(msg);
    int[] X = new int[16];

    for (int i = 0; i < padded.length; i += 64) {
      for (int j = 0; j < 16; j++) {
        int k = i + j*4;
        X[j] = ((padded[k] & 0xff)) |
          ((padded[k+1] & 0xff) << 8) |
          ((padded[k+2] & 0xff) << 16) |
          ((padded[k+3] & 0xff) << 24);
      }
      compress(h, X);
    }

    byte[] out = new byte[20];
    for (int i = 0; i < 5; i++) {
      int v = h[i];
      out[i*4]   = (byte)(v & 0xff);
      out[i*4+1] = (byte)((v >>> 8) & 0xff);
      out[i*4+2] = (byte)((v >>> 16) & 0xff);
      out[i*4+3] = (byte)((v >>> 24) & 0xff);
    }
    return out;
  }

  static byte[] pad(byte[] msg) {
    long bitLen = (long)msg.length * 8L;
    int padLen = 64 - (int)((msg.length + 8 + 1) % 64);
    if (padLen == 64) padLen = 0;
    byte[] out = new byte[msg.length + 1 + padLen + 8];
    System.arraycopy(msg, 0, out, 0, msg.length);
    out[msg.length] = (byte)0x80;
    int idx = out.length - 8;
    for (int i = 0; i < 8; i++) out[idx + i] = (byte)((bitLen >>> (8*i)) & 0xff);
    return out;
  }

  static int rol(int x, int s) { return (x << s) | (x >>> (32 - s)); }
  static int f(int j, int x, int y, int z) {
    if (j <= 15) return x ^ y ^ z;
    if (j <= 31) return (x & y) | (~x & z);
    if (j <= 47) return (x | ~y) ^ z;
    if (j <= 63) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }
  static int K(int j) {
    if (j <= 15) return 0x00000000;
    if (j <= 31) return 0x5a827999;
    if (j <= 47) return 0x6ed9eba1;
    if (j <= 63) return 0x8f1bbcdc;
    return 0xa953fd4e;
  }
  static int KK(int j) {
    if (j <= 15) return 0x50a28be6;
    if (j <= 31) return 0x5c4dd124;
    if (j <= 47) return 0x6d703ef3;
    if (j <= 63) return 0x7a6d76e9;
    return 0x00000000;
  }

  static final int[] r = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
  static final int[] rr = { 5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
  static final int[] s = { 11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
  static final int[] ss = { 8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };

  static void compress(int[] h, int[] X) {
    int al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    int ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

    for (int j = 0; j < 80; j++) {
      int T = rol(al + f(j, bl, cl, dl) + X[r[j]] + K(j), s[j]) + el;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = T;

      T = rol(ar + f(79 - j, br, cr, dr) + X[rr[j]] + KK(j), ss[j]) + er;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = T;
    }

    int temp = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = temp;
  }
}
