void drawDataRow(String label, String value, int y) {
  if (value != null && value.length() > 0) {
    fill(0, 255, 65, 180);
    text(label, 50, y);
    fill(255);
    text(value, 200, y);
  }
}


// ========================== EDITABLE FIELD ==========================
class Field {
  int x, y, w, h;
  String label;
  String value = "";
  boolean active = false;
  int caret = 0;
  int selStart = 0, selEnd = 0;

  Field(int x, int y, int w, int h, String label) {
    this.x = x;
    this.y = y;
    this.w = w;
    this.h = h;
    this.label = label;
  }

  void setValue(String s) {
    value = (s == null) ? "" : s;
    caret = constrain(caret, 0, value.length());
    clearSelection();
  }

  void drawField() {
    fill(active ? 30 : 15);
    stroke(active ? color(0, 255, 65) : color(80));
    strokeWeight(2);
    rect(x, y, w, h, 6);

    fill(active ? 255 : 150);
    textSize(16);
    text(label, x + 10, y - 12);

    float innerX = x + 15;
    float innerY = y + (h / 2) + 8;
    float maxW = w - 30;

    textSize(24); // Large Font
    int visStart = computeVisibleStart(maxW);
    String vis = value.substring(visStart);

    while (vis.length() > 0 && textWidth(vis) > maxW) vis = vis.substring(0, vis.length() - 1);

    if (active && hasSelection()) {
      int a = selMin(), b = selMax();
      int aV = max(a, visStart), bV = min(b, visStart + vis.length());
      if (bV > aV) {
        float lx = textWidth(value.substring(visStart, aV));
        float mw = textWidth(value.substring(aV, bV));
        noStroke();
        fill(0, 255, 65, 80);
        rect(innerX + lx, y + 8, mw, h - 16, 4);
      }
    }

    fill(0, 255, 65);
    text(vis, innerX, innerY);

    if (active && (millis() / 500) % 2 == 0) {
      int c = constrain(caret, visStart, visStart + vis.length());
      float cx = innerX + textWidth(value.substring(visStart, c));
      stroke(0, 255, 65);
      line(cx, y + 10, cx, y + h - 10);
    }
  }

  boolean hit(int mx, int my) {
    return mx > x && mx < x + w && my > y && my < y + h;
  }

  void clearSelection() {
    selStart = caret;
    selEnd = caret;
  }

  int selMin() {
    return min(selStart, selEnd);
  }

  int selMax() {
    return max(selStart, selEnd);
  }

  boolean hasSelection() {
    return selStart != selEnd;
  }

  void replaceSelection(String s) {
    int a = selMin(), b = selMax();
    value = value.substring(0, a) + s + value.substring(b);
    caret = a + s.length();
    clearSelection();
  }

  void deleteBack() {
    if (hasSelection()) {
      replaceSelection("");
      return;
    }
    if (caret <= 0) return;
    value = value.substring(0, caret - 1) + value.substring(caret);
    caret--;
    clearSelection();
  }

  void moveCaret(int delta, boolean shift) {
    caret = constrain(caret + delta, 0, value.length());
    if (shift) selEnd = caret;
    else clearSelection();
  }

  void clickSetCaretByMouse(int mx, boolean shift) {
    float innerX = x + 15;
    int visStart = computeVisibleStart(w - 30);
    String vis = value.substring(visStart);
    float rel = mx - innerX;
    int idx = 0;
    while (idx < vis.length() && textWidth(vis.substring(0, idx + 1)) < rel) idx++;
    caret = visStart + idx;
    if (shift) selEnd = caret;
    else clearSelection();
  }

  int computeVisibleStart(float maxW) {
    int visStart = 0;
    while (visStart < caret && textWidth(value.substring(visStart, caret)) > maxW) visStart++;
    return visStart;
  }
}
