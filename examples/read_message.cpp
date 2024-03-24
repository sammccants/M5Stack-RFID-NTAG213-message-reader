#include "NTAG213_reader.h"

NTAG213Reader nfc_reader;

void setup() {
  nfc_reader.begin();
}

void loop() {
  String message = nfc_reader.readMessageIfPresent();
  if (message.length() > 0) {
    Serial.println(message);
  }
}
