import java.security.MessageDigest;
import java.util.Arrays;
import java.math.BigInteger;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.PrintWriter;
import javax.swing.JFrame;
import java.io.File;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

ExecutorService executor;
AtomicBoolean isRunningPool = new AtomicBoolean(false);
AtomicLong totalTestedAtomic = new AtomicLong(0);
int numCores = Runtime.getRuntime().availableProcessors();

// Method to convert the target address into bytes (Hash160)
byte[] addressToHash160(String addr) {
  try {
    if (addr == null) return null;
    addr = addr.trim();

    // Bech32 / Bech32m (bc1... or tb1...)
    String lower = addr.toLowerCase();
    if (lower.startsWith("bc1") || lower.startsWith("tb1")) {
      // decodeSegwitAddress already validates checksum, hrp, version, and length
      return Bech32.decodeSegwitAddress(addr); // returns 20 or 32 bytes (or null)
    }

    // Base58Check (Legacy/P2SH)
    byte[] data = base58DecodeChecked(addr); // [version + payload], without checksum
    if (data == null || data.length != 21) return null;

    int ver = data[0] & 0xFF;

    // Mainnet: P2PKH=0x00, P2SH=0x05
    // (Optional: testnet: P2PKH=0x6F, P2SH=0xC4)
    if (!(ver == 0x00 || ver == 0x05 || ver == 0x6F || ver == 0xC4)) return null;

    return Arrays.copyOfRange(data, 1, 21); // 20 bytes hash160
  }
  catch (Exception e) {
    return null;
  }
}

// ========================== UI / STATE ==========================
String inputWIF = "";
String inputTargetAddr = "";
boolean focusWIF = true;

String statusMsg = "Click fields to edit.";
String privHex = "";
String pubHex = "";
String addrP2PKH = "";
String addrP2SH_P2WPKH = "";
String addrBECH32 = "";
String matchMsg = "";

final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

Field fieldWIF;
Field fieldTARGET;

BigInteger currentKey = BigInteger.ONE;
boolean scanning = false;

long startTime = 0;
String sessionStartTime = "";

volatile long jumpSize = 0;
volatile boolean randomMode = false; 
BigInteger normalModeResumeKey;

// ========================== SETUP / DRAW ==========================
void setup() {
  size(1020, 800);
  PFont mono = createFont("Consolas", 18);
  textFont(mono);

  JFrame frame = (JFrame) ((processing.awt.PSurfaceAWT.SmoothCanvas) surface.getNative()).getFrame();
  frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);

  // x, y, width, height, label
  fieldWIF    = new Field(50, 130, 920, 60, "PRIVATE KEY (WIF):");
  fieldTARGET = new Field(50, 240, 920, 60, "TARGET ADDRESS:");

  fieldWIF.setValue(inputWIF);
  fieldTARGET.setValue(inputTargetAddr);

  Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
    public void run() {
      if (scanning) {
        saveProgress(sanitize(inputTargetAddr), currentKey);
        System.out.println("Emergency save completed.");
      }
    }
  }
  ));
}

void draw() {
  background(10);

  // Header
  fill(0, 255, 65);
  textSize(22);
  textAlign(CENTER);
  text("BitBF - Bitcoin Wallet Key Scanner & Validator", width/2, 45);
  textAlign(LEFT);

  stroke(0, 255, 65, 80);
  line(50, 80, 970, 80);

  // Field Focus & Display
  fieldWIF.active    = focusWIF;
  fieldTARGET.active = !focusWIF;
  fieldWIF.drawField();
  fieldTARGET.drawField();

  // Metadata
  fill(140);
  textSize(14);
  text("WIF Length: " + sanitize(inputWIF).length(), 850, 220);
  text("Target Length: " + sanitize(inputTargetAddr).length(), 828, 325);

  // Status Info
  fill(200);
  textSize(16);
  text("Status: " + statusMsg, 50, 355);

  // Cryptographic Output
  textSize(16);
  drawDataRow("PRIV (hex):", privHex, 440);
  drawDataRow("PUB  (hex):", pubHex, 475);
  drawDataRow("P2PKH (Legacy):", addrP2PKH, 525);
  drawDataRow("P2SH (Nested):", addrP2SH_P2WPKH, 565);
  drawDataRow("P2WPKH (Bech32):", addrBECH32, 605);

  // Scanning UI
  if (scanning) {
    if (frameCount % 10 == 0) {
      String visualWIF = base58CheckEncodeWithCompression((byte)0x80, Secp256k1.toFixed32(currentKey), true);
      fieldWIF.setValue(visualWIF);
    }

    fill(255, 150, 0);
    textSize(20);
    text("● SCANNING IN PROGRESS...", 50, 670);
    textSize(18);

    // Formatting the number with commas for readability
    String formattedCount = String.format("%,d", totalTestedAtomic.get());
    text("TOTAL KEYS TESTED: " + formattedCount, 50, 705);

    long currentElapsed = (millis() - startTime) / 1000;
    text("Session Start: " + sessionStartTime, 700, 670);
    text("Elapsed Time: " + currentElapsed + "s", 700, 705);
  }

  // Result Output
  if (matchMsg.length() > 0) {
    textSize(22);
    if (matchMsg.contains("SUCCESS")) fill(0, 255, 65);
    else fill(255, 80, 80);
    text(matchMsg, 50, 400);
  }

  stroke(0, 255, 65, 80);
  line(50, 730, 970, 730);

  // Controls Footer
  fill(150);
  textSize(13);
  textAlign(CENTER);
  text("CONTROLS: [TAB] Switch Fields | [SHIFT + ALT] Paste | [SHIFT + CLICK] Paste | [SPACE] Manual Test | [ENTER] Toggle Brute Force ", width/2, 750);
  text("BRUTE FORCE: Use [A/D] to Jump, [S] for Random, [N] for Normal", width/2, 780);
  textAlign(LEFT);
}

void handleMatchFound(BigInteger foundKey, String target, String typeFound) {
  isRunningPool.set(false);
  scanning = false;
  long timeElapsedFinal = millis() - startTime;
  final String wif = base58CheckEncodeWithCompression((byte)0x80, Secp256k1.toFixed32(foundKey), true);

  javax.swing.SwingUtilities.invokeLater(() -> {
    inputWIF = wif;
    fieldWIF.setValue(wif);
    statusMsg = "MATCH FOUND!";
    generateReport(target, wif, typeFound, totalTestedAtomic.get(), timeElapsedFinal);
    processAndCompare(); // Update hex fields on screen
  }
  );

  if (executor != null) executor.shutdownNow();
}

// Save the current state to allow resuming later
void saveProgress(String target, BigInteger lastKey) {
  try {
    PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(sketchPath("Scan_progress.dat"), false)));
    pw.println(target + ":" + lastKey.toString(16));
    pw.close();
  }
  catch (Exception e) {
    println("Save Error: " + e.getMessage());
  }
}

// Load progress if the target address matches the one saved in the file
BigInteger loadProgress(String target) {
  try {
    File f = new File(sketchPath("Scan_progress.dat"));
    if (!f.exists()) return null;
    String[] lines = loadStrings("Scan_progress.dat");
    if (lines.length > 0) {
      String[] parts = lines[0].split(":");
      if (parts[0].equalsIgnoreCase(target)) {
        return new BigInteger(parts[1], 16);
      }
    }
  }
  catch (Exception e) {
    println("Load Error: " + e.getMessage());
  }
  return null;
}

// Generate a detailed text report upon finding a key
void generateReport(String target, String wif, String type, long tested, long elapsed) {
  try {
    PrintWriter report = new PrintWriter(new BufferedWriter(new FileWriter(sketchPath("Scan_Report.txt"), true)));
    report.println("--- BITCOIN KEY MATCH FOUND ---");
    report.println("Date: " + day() + "/" + month() + "/" + year());
    report.println("Session Started At: " + sessionStartTime);
    report.println("Target Address: " + target);
    report.println("Private Key (WIF): " + wif);
    report.println("Address Type: " + type);
    report.println("Total Keys Tested: " + tested);
    report.println("Time Elapsed: " + nf(elapsed / 1000.0f, 1, 2) + " seconds");
    report.println("-------------------------------");
    report.println();
    report.close();
  }
  catch (Exception e) {
    println("Report Error: " + e.getMessage());
  }
}


// ========================== INPUT HANDLING ==========================
public void mousePressed() {
  // Lock all field interactions if scanning is active
  if (scanning) return;

  boolean shift = keyPressed && (keyCode == SHIFT);

  if (fieldWIF.hit(mouseX, mouseY)) {
    focusWIF = true;
    fieldWIF.active = true;
    fieldTARGET.active = false;
    fieldWIF.clickSetCaretByMouse(mouseX, shift);

    // ONLY allows paste if SHIFT is held
    if (shift) {
      handlePaste(fieldWIF, true);
    }
  } else if (fieldTARGET.hit(mouseX, mouseY)) {
    focusWIF = false;
    fieldWIF.active = false;
    fieldTARGET.active = true;
    fieldTARGET.clickSetCaretByMouse(mouseX, shift);

    // ONLY allows paste if SHIFT is held
    if (shift) {
      handlePaste(fieldTARGET, false);
    }
  }
}

void handlePaste(Field f, boolean isWifField) {
  boolean shift = keyPressed && (keyCode == SHIFT);
  
  if (shift && !scanning) {
    String pasted = sanitize(pasteFromClipboard());
    if (pasted != null && !pasted.isEmpty()) {
      f.setValue(pasted);
      syncFieldToStrings();
      resetOut();
      statusMsg = "Clipboard pasted.";
    }
  }
}

void keyPressed() {
  // Check for modifier keys
  boolean shift = (keyEvent != null) && keyEvent.isShiftDown();
  boolean ctrl  = (keyEvent != null) && keyEvent.isControlDown();

  // SCANNING CONTROLS (Active while scanning)
  if (scanning) {
    if (key == 'a' || key == 'A') {
      jumpSize += 1000000; 
      statusMsg = "MANUAL JUMP: +" + String.format("%,d", jumpSize) + " keys/cycle";
    }
    
    if (key == 'd' || key == 'D') {
      jumpSize -= 1000000; 
      statusMsg = "MANUAL JUMP: " + String.format("%,d", jumpSize) + " keys/cycle";
    }

    if (key == 's' || key == 'S') {
      if (!randomMode) {
        normalModeResumeKey = currentKey;
        randomMode = true;
        jumpSize = 0;
      }
      statusMsg = "MODE: RANDOM BLOCKS (50k keys per block)";
    }

    if (key == 'n' || key == 'N') {
      randomMode = false;
      jumpSize = 0;
      if (normalModeResumeKey != null) currentKey = normalModeResumeKey;
      statusMsg = "MODE: NORMAL SEQUENTIAL (Resumed)";
    }
    
    if (keyCode == BACKSPACE || keyCode == DELETE) return;
  }
  
  // GLOBAL CONTROLS
  if (keyCode == ENTER) {
    syncFieldToStrings();
    scan();
    return;
  }

  // If scanning, stop execution here to prevent modification
  if (scanning) return;

  // KEYBOARD PASTE FUNCTION (SHIFT + CONTROL)
  // Triggers when BOTH are held down
  if (shift && ctrl) {
    Field activeField = focusWIF ? fieldWIF : fieldTARGET;
    
    String pasted = sanitize(pasteFromClipboard());
    if (pasted != null && !pasted.isEmpty()) {
      activeField.setValue(pasted);
      syncFieldToStrings();
      resetOut();
      statusMsg = "Clipboard pasted via SHIFT+CTRL.";
    }
    return; // Exit to prevent other key behaviors
  }

  // NORMAL EDITING CONTROLS (Only when idle)
  if (keyCode == TAB) {
    focusWIF = !focusWIF;
    syncFieldToStrings();
    Field f = focusWIF ? fieldWIF : fieldTARGET;
    f.clearSelection();
    return;
  }
  
  if (key == ' ') {
    syncFieldToStrings();
    processAndCompare();
    return;
  }

  Field f = focusWIF ? fieldWIF : fieldTARGET;
  if (keyCode == LEFT) f.moveCaret(-1, shift);
  if (keyCode == RIGHT) f.moveCaret(1, shift);
  
  if (keyCode == BACKSPACE || keyCode == DELETE) {
    f.deleteBack();
    resetOut();
  }
  syncFieldToStrings();
}

void keyTyped() {
  // Completely block character input while scanning
  if (scanning) return;
  
  // UPDATED: Added DELETE to the ignore list for keyTyped
  if (key == CODED || key == ESC || key == TAB || key == ENTER || key == BACKSPACE || key == DELETE) return;
  
  Field f = focusWIF ? fieldWIF : fieldTARGET;
  if (Character.isWhitespace(key)) return;
  f.replaceSelection(str(key));
  syncFieldToStrings();
  resetOut();
}

void syncFieldToStrings() {
  inputWIF = fieldWIF.value;
  inputTargetAddr = fieldTARGET.value;
}

void exit() {
  if (scanning) {
    statusMsg = "CANNOT CLOSE: Scan in progress! Pause (ENTER) first.";
  } else {
    super.exit();
  }
}
