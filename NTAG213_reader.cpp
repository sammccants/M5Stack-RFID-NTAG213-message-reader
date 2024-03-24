#include <Arduino.h>
#include <Wire.h>

#include "NTAG213_reader.h"
#include "MFRC522_I2C.h"


NTAG213Reader::NTAG213Reader() : _mfrc522(DEFAULT_CHIP_ADDRESS) {
}


NTAG213Reader::NTAG213Reader(byte chipAddress) : _mfrc522(chipAddress) {
}

void NTAG213Reader::begin() {
  Serial.begin(115200);

  Wire.begin();
  _mfrc522.PCD_Init();
}


void NTAG213Reader::printMemoryInPageRange(byte startPage, byte endPage) {
  if (startPage > MAX_NTAG213_PAGE || endPage > MAX_NTAG213_PAGE) {
      DEBUGLN("Pages must be between 0 and 44! Probably gonsta crash now...");
  } else if (startPage > endPage) {
      DEBUGLN("startPage must be <= endPage (to actually get anything back)!");
  }

  byte buffer[18];  // Buffer to store the read data
  byte bufferSize = sizeof(buffer);
  byte readResult;

  DEBUGLN(F("Reading and decoding pages..."));
  String decodedMessage = "";  // String to accumulate the decoded message
  for (byte page = startPage; page <= endPage; page++) {
    DEBUGLN();
    readResult = _mfrc522.MIFARE_Read(page, buffer, &bufferSize);
    if (readResult == MFRC522::STATUS_OK) {
      // Decode each byte in the buffer except the last 2 bytes which are CRC
      // bytes
      for (byte i = 0; i < 4; i++) {
        DEBUG("page: ");
        DEBUG(page);
        DEBUG(", byte ");
        DEBUG(i);
        DEBUG(": ");
        DEBUGB(buffer[i], HEX);

        // printable ASCII range
        if (buffer[i] >= 32 && buffer[i] <= 126) {
          decodedMessage += (char)buffer[i];

          DEBUG(" (");
          DEBUG((char)buffer[i]);
          DEBUGLN(")");
        } else {
          decodedMessage += ".";
          DEBUGLN();
        }
      }
    } else {
      DEBUG(F("Reading failed for page "));
      DEBUG(page);
      DEBUG(F(" with error: "));
      DEBUGLN(_mfrc522.GetStatusCodeName(readResult));
      break;  // Exit loop on error
    }
  }
  DEBUGLN(decodedMessage);

  // Halt PICC and stop encryption on PCD
  _mfrc522.PICC_HaltA();
  _mfrc522.PCD_StopCrypto1();
}


void NTAG213Reader::printMemoryInPageRangeIfPresent(byte startPage, byte endPage) {
  // Look for new cards
  if (!_mfrc522.PICC_IsNewCardPresent() || !_mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  printMemoryInPageRange(startPage, endPage);
}


void NTAG213Reader::readMessageRecursively(byte *buffer, byte messageContentStartByte,
                            byte messageContentEndByte, String &fullMessageContent,
                            byte currentPage, byte &bufferSize) {
  for (
    byte i = messageContentStartByte;
    i < min(16, (int)messageContentEndByte);
    i++
  ) {
    if (buffer[i] >= 32 && buffer[i] <= 126) {
      fullMessageContent += (char)buffer[i];
    } else {
      DEBUG(F("Non-ASCII byte found in message at byte "));
      DEBUG(i);
      DEBUG(F(": "));
      DEBUGLNB(buffer[i], HEX);
    }
  }

  if (messageContentEndByte > 16) {
    DEBUG(F("Message end byte of "));
    DEBUG(messageContentEndByte);
    DEBUGLN(F(" goes beyond buffer size! We must go depthier..."));

    messageContentStartByte = 0;
    messageContentEndByte -= 16;
    byte readResultStatus = _mfrc522.MIFARE_Read(currentPage + 4, buffer, &bufferSize);
    if (readResultStatus == MFRC522::STATUS_OK) {
      readMessageRecursively(buffer, messageContentStartByte, messageContentEndByte, fullMessageContent, currentPage + 4, bufferSize);
    }
  }
}


void NTAG213Reader::processNdefMessage(byte *buffer, byte messageStartByte, String &fullMessageContent,
                        byte currentPage, byte &bufferSize) {
  // TODO: will currently only work with single-record, Well-Known (TNF), Text (type) messages
  if (
    (buffer[messageStartByte] != EXPECTED_RECORD_HEADER)
    || (buffer[messageStartByte + 1] != EXPECTED_TYPE_LENGTH)
    || (buffer[messageStartByte + 3] != EXPECTED_TYPE)
  ) {
    DEBUGLN(F("Unexpected NDEF message format; skipping..."));
    return;
  }
  // value of length byte + length byte itself
  const byte languageInfoLength = buffer[messageStartByte + 4] + 1;
  const byte messageContentStartByte = messageStartByte + 4 + languageInfoLength;
  // language info is included in length
  const byte messageContentEndByte = (messageStartByte + 4) + buffer[messageStartByte + 2];

  // finally read the actual message!
  readMessageRecursively(buffer, messageContentStartByte, messageContentEndByte,
                         fullMessageContent, currentPage, bufferSize);
}


byte NTAG213Reader::readNextTlvBlock(byte &currentByte, byte &bufferSize,
                      byte *buffer, String &fullMessageContent) {
  DEBUG(F("Reading TLV block starting at byte "));
  DEBUGLN(currentByte);
  byte readResultStatus = _mfrc522.MIFARE_Read(currentByte / 4, buffer, &bufferSize);
  if (readResultStatus == MFRC522::STATUS_OK) {
    const byte blockStartByte = currentByte % 4;
    // buffer[blockStartByte + 1] is the [L]ength of the block [V]alue,
    // plus 1 each for the T & L bytes
    const byte currentBlockLength = 2 + buffer[blockStartByte + 1];

    // buffer[blockStartByte] is the first byte of the block, which is the TLV [T]ag
    switch(buffer[blockStartByte]) {

      case LOCK_CONTROL_TLV_TAG:
        DEBUGLN(F("Lock Control tag found; skipping to next block..."));
        currentByte += currentBlockLength;
        return 0;

      case NDEF_MESSAGE_TLV_TAG:
        DEBUGLN(F("NDEF Message tag found; processing message..."));
        processNdefMessage(buffer, blockStartByte + 2, fullMessageContent, currentByte / 4, bufferSize);
        currentByte += currentBlockLength;
        return 0;

      case TERMINATOR_TLV_TAG:
        DEBUGLN(F("Terminator tag found; ending..."));
        return 1;

      default:
        DEBUG(F("Unknown TLV tag found ("));
        DEBUGB(buffer[blockStartByte], HEX);
        DEBUGLN(F("); ending..."));
        return 1;
    }

  } else {
    DEBUG(F("Reading failed with error: "));
    DEBUGLN(_mfrc522.GetStatusCodeName(readResultStatus));
    return 1;
  }
}


String NTAG213Reader::readMessage() {
  byte current_page = 4;
  // For NTAG213, pages 0-2 contain the serial number & lock bytes,
  // page 3 is CC, and page 4-39 is NDEF message; each page has 4 bytes
  // We'll start with the first byte of the message pages
  byte currentByte = 16;

  byte buffer[18];  // Buffer to store the read data
  byte bufferSize = sizeof(buffer);
  byte readResultStatus;

  String fullMessageContent = ""; // String to accumulate the decoded message

  byte messageTerminated = 0;
  while (!messageTerminated) {
    messageTerminated = readNextTlvBlock(currentByte, bufferSize, buffer, fullMessageContent);
  }

  // Halt PICC and stop encryption on PCD
  _mfrc522.PICC_HaltA();
  _mfrc522.PCD_StopCrypto1();

  return fullMessageContent;
}


String NTAG213Reader::readMessageIfPresent() {
  // Look for new cards
  if (!_mfrc522.PICC_IsNewCardPresent() || !_mfrc522.PICC_ReadCardSerial()) {
    // TODO: throw error instead?
    return "";
  }

  return readMessage();
}
