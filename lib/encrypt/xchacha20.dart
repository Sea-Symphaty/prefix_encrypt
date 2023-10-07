import 'res.dart';

import 'chacha20_prefix.dart';
import 'h_chacha20.dart';

/// With XChaCha20, regardless of whether with or without prefix, a block is created first with the HChaCha20 and the first and last four elements are
/// taken from this as the new key. For the key creation the first 32 bytes are taken. The nonce is taken for the block consists of 8 zeros, followed
/// by the remaining 16 bytes of the nonce. The encrypted text is then generated using ChaCha20 and the new key and nonce.

class XChaCha20withPrefix {
  static Future<String> encrypt(
      {required String key,
      required String nonce,
      required String plaintext}) async {
    if (key.length != 64) {
      throw ("XChaCha20 encrypt\nKey must be 64 character.");
    } else if (nonce.length != 48) {
      throw ("XChaCha20 encrypt\nNonce must be 48 character.");
    } else {
      List nonceList = [
        for (int a = 0; a < 48; a += 8) nonce.substring(a, a + 8)
      ];
      String subkey =
          hChaCha20block(stringHexToListHex(key), nonceList.sublist(0, 4));
      List chacha20nonce = ["00000000"];
      chacha20nonce.addAll(nonceList.sublist(4, 6));

      return ChaCha20withPrefix.encrypt(
          stringHexToListHex(subkey),
          1,
          stringHexToListHex(chacha20nonce.join()),
          stringTextToListHexPrefix(plaintext));
    }
  }

  static Future<String> decrypt(
      {required String key,
      required String nonce,
      required String ciphertext}) async {
    if (key.length != 64) {
      throw ("XChaCha20 decrypt\nKey must be 64 character.");
    } else if (nonce.length != 48) {
      throw ("XChaCha20 decrypt\nNonce must be 48 character.");
    } else {
      List nonceList = [
        for (int a = 0; a < 48; a += 8) nonce.substring(a, a + 8)
      ];
      String subkey =
          hChaCha20block(stringHexToListHex(key), nonceList.sublist(0, 4));
      List chacha20nonce = ["00000000"];
      List ciphertextList = stringHexTo128HexList(ciphertext);
      chacha20nonce.addAll(nonceList.sublist(4, 6));
      return ChaCha20withPrefix.decrypt(
          stringHexToListHex(subkey),
          1,
          stringHexToListHex(chacha20nonce.join()),
          bigIntHexList(ciphertextList));
    }
  }
}

class XChaCha20 {
  static Future<String> encrypt(
      {required String key,
      required String nonce,
      required String plaintext}) async {
    if (key.length != 64) {
      throw ("XChaCha20 encrypt\nKey must be 64 character.");
    } else if (nonce.length != 48) {
      throw ("XChaCha20 encrypt\nNonce must be 48 character.");
    } else {
      List nonceList = [
        for (int a = 0; a < 48; a += 8) nonce.substring(a, a + 8)
      ];
      String subkey =
          hChaCha20block(stringHexToListHex(key), nonceList.sublist(0, 4));
      List chacha20nonce = ["00000000"];
      chacha20nonce.addAll(nonceList.sublist(4, 6));

      return ChaCha20.encrypt(
          stringHexToListHex(subkey),
          1,
          stringHexToListHex(chacha20nonce.join()),
          stringTextToListHex(plaintext));
    }
  }

  static Future<String> decrypt(
      {required String key,
      required String nonce,
      required String ciphertext}) async {
    if (key.length != 64) {
      throw ("XChaCha20 decrypt\nKey must be 64 character.");
    } else if (nonce.length != 48) {
      throw ("XChaCha20 decrypt\nNonce must be 48 character.");
    } else {
      List nonceList = [
        for (int a = 0; a < 48; a += 8) nonce.substring(a, a + 8)
      ];
      String subkey =
          hChaCha20block(stringHexToListHex(key), nonceList.sublist(0, 4));
      List chacha20nonce = ["00000000"];
      List ciphertextList = stringHexTo128HexList(ciphertext);
      chacha20nonce.addAll(nonceList.sublist(4, 6));
      return ChaCha20.decrypt(
          stringHexToListHex(subkey),
          1,
          stringHexToListHex(chacha20nonce.join()),
          bigIntHexList(ciphertextList));
    }
  }
}
