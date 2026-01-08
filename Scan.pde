// ========================== SCANNING ENGINE ==========================
void scan() {
  if (isRunningPool.get()) {
    stopScanning();
    return;
  }

  String target = sanitize(inputTargetAddr);
  if (target.isEmpty()) {
    statusMsg = "Error: Target address required.";
    return;
  }

  BigInteger safetyOffset = new BigInteger("10000");

  resetOut();
  statusMsg = "SCANNING: Use [A/D] to Jump, [S] for Random, [N] for Normal";

  // 1. Set Starting Point - Priority: WIF Field > Saved Progress > Start
  if (!inputWIF.isEmpty()) {
    try {
      byte[] decoded = base58DecodeChecked(inputWIF);
      if (decoded != null && decoded.length >= 33) {
        BigInteger fieldKey = new BigInteger(1, Arrays.copyOfRange(decoded, 1, 33));

        // Apply robustness: Subtract offset to start earlier
        if (fieldKey.compareTo(safetyOffset) > 0) {
          currentKey = fieldKey.subtract(safetyOffset);
          statusMsg = "Starting 100k keys before provided WIF...";
        } else {
          currentKey = BigInteger.ONE;
          statusMsg = "WIF too low, starting from key 1.";
        }
      } else {
        currentKey = null; // Mark to check next priority
      }
    }
    catch (Exception e) {
      currentKey = null;
    }
  }

  // 2. Fallback to Saved Progress
  if (currentKey == null) {
    BigInteger saved = loadProgress(target);
    if (saved != null) {
      currentKey = saved;
      statusMsg = "Resuming from saved progress...";
    } else {
      currentKey = BigInteger.ONE;
      statusMsg = "Starting from key 1.";
    }
  }

  // State setup
  isRunningPool.set(true);
  scanning = true;
  startTime = millis();
  sessionStartTime = hour() + ":" + nf(minute(), 2) + ":" + nf(second(), 2);
  totalTestedAtomic.set(0);

  if (executor != null && !executor.isTerminated()) executor.shutdownNow();
  executor = Executors.newFixedThreadPool(numCores);

  final byte[] targetBytes = addressToHash160(target);

  for (int i = 0; i < numCores; i++) {
    executor.execute(() -> {
      while (isRunningPool.get()) {
        try {
          BigInteger threadKey;

          synchronized(this) {
            
            if (randomMode) {
              
              if (totalTestedAtomic.get() % 50000 == 0) {
                // Gera um BigInteger aleatório de 256 bits
                java.util.Random rnd = new java.util.Random();
                currentKey = new BigInteger(256, rnd);
              }
            }

            
            if (jumpSize != 0) {
              currentKey = currentKey.add(BigInteger.valueOf(jumpSize));
            }

            threadKey = currentKey;
            currentKey = currentKey.add(BigInteger.ONE);
          }

          
          byte[] pub = Secp256k1.publicKeyFromPrivate(threadKey, true);
          byte[] h160 = hash160(pub);

          if (Arrays.equals(h160, targetBytes)) {
            handleMatchFound(threadKey, target, "SUCCESS!");
            break;
          }

          totalTestedAtomic.incrementAndGet();
        }
        catch (Exception e) {
        }
      }
    }
    );
  }
}

void stopScanning() {
  isRunningPool.set(false);
  scanning = false;

  if (executor != null) {
    executor.shutdownNow();
    try {
      if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }
    }
    catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  saveProgress(sanitize(inputTargetAddr), currentKey);
  statusMsg = "Scan paused. Progress saved.";
}
