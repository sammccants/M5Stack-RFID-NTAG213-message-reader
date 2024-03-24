#ifndef NTAG213_READER_H
#define NTAG213_READER_H

#include <Arduino.h>
#include "MFRC522_I2C.h"

// DEBUG LOGS
#define DEBUG_LOG_ENABLED 0

#if DEBUG_LOG_ENABLED

#define DEBUG(x) Serial.print(x)
#define DEBUGB(x, y) Serial.print(x, y)
#define DEBUGLN(x) Serial.println(x)
#define DEBUGLNB(x, y) Serial.println(x, y)

#else

#define DEBUG(x)
#define DEBUGB(x, y)
#define DEBUGLN(x)
#define DEBUGLNB(x, y)

#endif


// CONSTANTS

constexpr byte LOCK_CONTROL_TLV_TAG = 0x01;
constexpr byte NDEF_MESSAGE_TLV_TAG = 0x03;
constexpr byte TERMINATOR_TLV_TAG = 0xFE;

// single-record, Well-Known (TNF) message record header
constexpr byte EXPECTED_RECORD_HEADER = 0xD1;
// Type should be T (0x54) meaning Text
constexpr byte EXPECTED_TYPE_LENGTH = 0x01;
constexpr byte EXPECTED_TYPE = 0x54;

constexpr byte DEFAULT_CHIP_ADDRESS = 0x28;

constexpr byte MAX_NTAG213_PAGE = 44;


class NTAG213Reader {
public:
    NTAG213Reader();
    NTAG213Reader(byte chipAddress);
    void begin();
    void printMemoryInPageRangeIfPresent(byte startPage, byte endPage);
    String readMessageIfPresent();

private:
    MFRC522 _mfrc522;
    String readMessage();
    void printMemoryInPageRange(byte startPage, byte endPage);
    byte readNextTlvBlock(byte &currentByte, byte &bufferSize,
                          byte *buffer, String &fullMessageContent);
    void readMessageRecursively(byte *buffer, byte messageContentStartByte,
                                byte messageContentEndByte, String &fullMessageContent,
                                byte currentPage, byte &bufferSize);
    void processNdefMessage(byte *buffer, byte messageStartByte, String &fullMessageContent,
                        byte currentPage, byte &bufferSize);
};


#endif
