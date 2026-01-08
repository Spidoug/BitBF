// ========================== CRYPTO & UTILS ==========================
void processAndCompare() {
  resetOut();
  String wif = sanitize(inputWIF);
  String target = sanitize(inputTargetAddr);

  if (wif.isEmpty() || target.isEmpty()) {
    statusMsg = "Error: Fill both fields.";
    return;
  }

  try {
    // -------- 1) Decode WIF with checksum validation --------
    // Expected: [version(1) + privkey(32) (+ 0x01 if compressed)]
    byte[] payload = base58DecodeChecked(wif);  // <-- MUST validate checksum
    if (payload == null) throw new RuntimeException("Invalid WIF (Base58Check).");

    if (!(payload.length == 33 || payload.length == 34)) {
      throw new RuntimeException("Invalid WIF length (payload=" + payload.length + ").");
    }

    int wifVer = payload[0] & 0xFF; // 0x80 mainnet, 0xEF testnet
    if (!(wifVer == 0x80 || wifVer == 0xEF)) {
      throw new RuntimeException("Invalid WIF version byte: 0x" + hex2(wifVer));
    }

    boolean compressed = false;
    if (payload.length == 34) {
      if ((payload[33] & 0xFF) != 0x01) {
        throw new RuntimeException("Invalid compressed WIF (missing 0x01 suffix).");
      }
      compressed = true;
    }

    byte[] priv = Arrays.copyOfRange(payload, 1, 33);
    privHex = toHex(priv);

    // -------- 2) Decide network from TARGET (recommended) --------
    // This avoids mismatch when user pastes a mainnet WIF but is testing a testnet address (or vice-versa).
    boolean targetIsTestnet = false;
    String lowerT = target.toLowerCase();
    if (lowerT.startsWith("tb1") || target.startsWith("m") || target.startsWith("n") || target.startsWith("2")) {
      targetIsTestnet = true;
    }
    // If you prefer to trust WIF instead:
    // boolean targetIsTestnet = (wifVer == 0xEF);

    byte p2pkhVer = (byte)(targetIsTestnet ? 0x6F : 0x00);
    byte p2shVer  = (byte)(targetIsTestnet ? 0xC4 : 0x05);
    String hrp    = targetIsTestnet ? "tb" : "bc";

    // -------- 3) Derive public key / addresses --------
    BigInteger d = new BigInteger(1, priv);
    // Optional but good: check 1 <= d < n (secp256k1 order)
    if (d.signum() <= 0 || d.compareTo(Secp256k1.N) >= 0) {
      throw new RuntimeException("Invalid private key range.");
    }

    byte[] pub = Secp256k1.publicKeyFromPrivate(d, compressed);
    pubHex = toHex(pub);

    byte[] pHash = hash160(pub); // 20 bytes

    // 1) Legacy P2PKH
    addrP2PKH = base58CheckEncode(p2pkhVer, pHash);

    // 2) Native SegWit P2WPKH (bech32 v0)
    addrBECH32 = Bech32.encodeSegwitAddress(hrp, 0, pHash);

    // 3) Nested SegWit P2SH-P2WPKH
    byte[] redeem = new byte[22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    System.arraycopy(pHash, 0, redeem, 2, 20);
    addrP2SH_P2WPKH = base58CheckEncode(p2shVer, hash160(redeem));

    // -------- 4) Compare (bech32 is case-insensitive) --------
    String typeFound = "";
    if (target.equals(addrP2PKH)) typeFound = "Legacy (P2PKH)";
    else if (lowerT.equals(addrBECH32.toLowerCase())) typeFound = "Native SegWit (Bech32)";
    else if (target.equals(addrP2SH_P2WPKH)) typeFound = "Nested SegWit (P2SH-P2WPKH)";

    if (!typeFound.isEmpty()) {
      matchMsg = "SUCCESS: MATCH FOUND (" + typeFound + ")";
      statusMsg = "Validation complete.";
    } else {
      matchMsg = "NO MATCH FOUND";
      statusMsg = "Validation complete (no match).";
    }
  }
  catch (Exception e) {
    statusMsg = "Error: " + e.getMessage();
  }
}

void resetOut() {
  privHex = "";
  pubHex = "";
  addrP2PKH = "";
  addrP2SH_P2WPKH = "";
  addrBECH32 = "";
  matchMsg = "";
}
