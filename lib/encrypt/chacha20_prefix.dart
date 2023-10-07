import 'res.dart';
import 'dart:math';

/// This is what a block looks like in ChaCha:
/// 0  1  2  3
/// 4  5  6  7
/// 8  9  10 11
/// 12 13 14 15
/// Each element (number) in the matrix consists of 32 bits or 8 hexadecimal numbers.
///
/// The key consists of 256 bits (64 bytes)
/// The nonce consists of 96 bits (24 bytes)
/// The block counter consists of 32 bits (8 bytes)
///
/// The encrypted text (ciphertext) consists of 64 bytes (512 bits or 128 hexadecimal values)
///
/// The elements 0 to 3 are constant values
/// The elements 4 to 11 are the key (64 bytes)
/// The element 12 is the block counter
/// The elements 13 to 15 are the nonce
/// c c c c | c = constant
/// k k k k | k = Key (encrypted password)
/// k k k k
/// b n n n | b = block counter, n = nonce
///
/// The nonce must be changed each time a new plaintext is created for encryption.
///
class ChaCha20withPrefix {
  static String encrypt(key, counter, nonce, List plaintext) {
    /// The text encryption is the same as for ChaCha20.
    List encryptedMessage = [];

    for (int a = 0; a < plaintext.length; a++) {
      BigInt keyStream = chacha20block(key, counter + a, nonce);
      BigInt block = plaintext[a];
      String keyStreamHex = keyStream.toRadixString(16);
      String blockHex = block.toRadixString(16);
      if (blockHex.length < keyStreamHex.length) {
        keyStreamHex = isNotEven(keyStreamHex);
        blockHex = isNotEven(blockHex);

        int diffBlockKeyStream = keyStreamHex.length - blockHex.length;
        keyStreamHex =
            keyStreamHex.substring(0, keyStreamHex.length - diffBlockKeyStream);

        keyStream = BigInt.parse(keyStreamHex, radix: 16);
      }

      encryptedMessage.add(keyStream ^ block);
    }

    List encryptedMessageDec = [];
    for (int a = 0; a < encryptedMessage.length; a++) {
      String string = encryptedMessage[a].toRadixString(16);
      string = isNotEven(string);
      encryptedMessageDec.add(string);
    }

    return encryptedMessageDec.join();
  }

  static String decrypt(List key, int counter, List nonce, List ciphertext) {
    String decryptHexString = encrypt(key, counter, nonce, ciphertext);
    String errorText =
        "The decrypted text does not have the same length as the plaintext.";
    String clearText = "";
    int clearTextLength = 0;

    List symbolLength = [];
    List symbolPosition = [];

    for (int a = 0; a < decryptHexString.length; a += 2) {
      if (a == 0) {
        /// The length of the text is determined here and, if available, the positions and lengths of the symbols.
        String tempString = "";

        for (int b = 0; b < decryptHexString.length; b += 2) {
          int charCode =
              int.parse(decryptHexString.substring(b, b + 2), radix: 16);
          tempString = tempString + String.fromCharCode(charCode);
          if (tempString.endsWith(":")) {
            tempString = tempString.substring(0, tempString.length - 1);

            if (tempString.split(".").length == 1) {
              clearTextLength = int.parse(tempString);
              tempString = "";
            } else {
              List split = tempString.split(".");
              symbolPosition.add(int.parse(split[0]));
              symbolLength.add(int.parse(split[1]));
              tempString = "";
            }
          } else if (tempString.endsWith(";")) {
            decryptHexString =
                decryptHexString.substring(b - 2, decryptHexString.length);
            a = 2;
            b = decryptHexString.length;
          }
        }
      } else if (symbolPosition.isNotEmpty && a == symbolPosition.first) {
        /// If the first position in the symbol position list matches the hexadecimal value available for conversion, then it is converted and added
        /// to the text. The "a" counter is then incremented by two or four, depending on the length of the symbol, because the symbols larger than
        /// 0xFF are rendered with four or six characters. At the end, the position and the length are deleted so that
        /// no index is needed for the condition.
        int charCode = int.parse(
            decryptHexString.substring(a, a + symbolLength.first as int),
            radix: 16);
        clearText = clearText + String.fromCharCode(charCode);
        symbolLength.first == 6 ? a += 4 : a += 2;
        symbolLength.removeAt(0);
        symbolPosition.removeAt(0);
      } else {
        /// Here the Latin letters, numbers and special characters are converted into readable script.
        int charCode =
            int.parse(decryptHexString.substring(a, a + 2), radix: 16);
        clearText = clearText + String.fromCharCode(charCode);
      }
    }

    return clearText.length == clearTextLength ? clearText : errorText;
  }
}

class ChaCha20 {
  static String encrypt(List key, int counter, List nonce, List plaintext) {
    List<BigInt> encryptedMessage = [];

    /// Each part of the plaintext is charged with a block. After each round a completely new block is created, as the block counter also continues
    /// to count up.
    for (int a = 0; a < plaintext.length; a++) {
      BigInt keyStream = chacha20block(key, counter + a, nonce);
      BigInt block = plaintext[a];

      /// Checks if the two lengths of the plaintext element and the block are the same. If one of the two has an odd number of characters, then a "0"
      /// is placed at the beginning. If the length of the two elements is not equal, then the difference is subtracted from the last characters of
      /// the block so that the length fits.
      String keyStreamHex = keyStream.toRadixString(16);
      String blockHex = block.toRadixString(16);
      if (blockHex.length < keyStreamHex.length) {
        keyStreamHex = isNotEven(keyStreamHex);
        blockHex = isNotEven(blockHex);

        int diffBlockKeyStream = keyStreamHex.length - blockHex.length;
        keyStreamHex =
            keyStreamHex.substring(0, keyStreamHex.length - diffBlockKeyStream);

        keyStream = BigInt.parse(keyStreamHex, radix: 16);
      }

      /// With XOR the current plaintext element is offset against the block.
      encryptedMessage.add(keyStream ^ block);
    }

    /// The individual encoded text elements are converted to hexadecimal, joined together and then output as a whole string.
    List encryptedMessageDec = [];
    for (int a = 0; a < encryptedMessage.length; a++) {
      String string = encryptedMessage[a].toRadixString(16);
      string = isNotEven(string);
      encryptedMessageDec.add(string);
    }

    return encryptedMessageDec.join();
  }

  static String decrypt(List key, int counter, List nonce, List ciphertext) {
    String decryptHexString = encrypt(key, counter, nonce, ciphertext);
    String clearText = "";

    /// The decrypted text is converted from hexadecimal to readable text.
    for (int a = 0; a < decryptHexString.length; a += 2) {
      int charCode = int.parse(decryptHexString.substring(a, a + 2), radix: 16);
      clearText = clearText + String.fromCharCode(charCode);
    }

    return clearText;
  }
}

/// Here the block is created with the elements from the constants, key, block counter and the nonce.
BigInt chacha20block(List key, int counter, List nonce) {
  List block = key + nonce;
  List initialState = [];

  /// The hexadecimal must be rotated per two bytes in each element except the constants and the block counter. 1A 1B 1C 1D becomes A1 B1 C1 D1.
  /// At the end the constants and the block counter are added and the block is added to to a temporary list.
  block = [for (int a = 0; a < 11; a++) serialize(block[a])];
  block.insertAll(
      0, ["61707865", "3320646e", "79622d32", "6b206574"]); // Konstante
  block = [for (int a = 0; a < 15; a++) int.parse(block[a], radix: 16)];
  block.insert(12, counter);
  initialState.addAll(block);

  /// Now the block is encrypted. This runs through 10 rounds, whereby per round the whole block is completely encrypted twice.
  for (var i = 0; i < 10; i++) {
    innerBlock(block);
  }

  /// The encrypted block is then compared with the original block. Each element is added and with modulo 2^32 you get the result
  /// which is turned back at the end.
  block = [
    for (int a = 0; a < 16; a++) ((block[a] + initialState[a]) % pow(2, 32))
  ];
  block = [
    for (int a = 0; a < 16; a++)
      serialize(isNotEven(block[a].toRadixString(16)))
  ];

  return bigIntHexList(block)[0];
}
