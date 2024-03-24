#include "NTAG213_reader.h"

NTAG213Reader nfc_reader;

void setup() {
  nfc_reader.begin();
}

void loop() {
  nfc_reader.printMemoryInPageRangeIfPresent(0, 44);
}
