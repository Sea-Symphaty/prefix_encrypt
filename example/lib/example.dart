import 'package:flutter/cupertino.dart';
import 'package:prefix_encrypt/prefix_encrypt.dart';

void main() {
  // all values have to be in hexadecimal

  String aad = "000000000000000000000000"; // must be at least 1 character
  String key =
      "0000000000000000000000000000000000000000000000000000000000000000"; // Key must be 64 character
  String iv = "0000000000000000"; // must be at least 16 character
  String constant = "00000000"; // must be 8 character
  String hNonce =
      "000000000000000000000000000000000000000000000000"; // must be 48 character
  String plaintextPrefix = "Hello World!😄";
  String plaintextWithoutPrefix = "Hello World!";

  Future<void> aeadXchacha20poly1305prefix() async {
    List encrypt = await AEADxChaCha20poly1305withPrefix.encrypt(
        aad: aad,
        iv: iv,
        key: key,
        constant: constant,
        hNonce: hNonce,
        plaintext: plaintextPrefix);
    String decrypt = await AEADxChaCha20poly1305withPrefix.decrypt(
        aad: aad,
        iv: iv,
        key: key,
        constant: constant,
        hNonce: hNonce,
        ciphertext: encrypt[0],
        savedTag: encrypt[1]);

    debugPrint("$encrypt\n$decrypt");
  }

  Future<void> xChaChaPrefix() async {
    String encrypt = await XChaCha20withPrefix.encrypt(
        key: key, nonce: hNonce, plaintext: plaintextPrefix);
    String decrypt = await XChaCha20withPrefix.decrypt(
        key: key, nonce: hNonce, ciphertext: encrypt);

    debugPrint("$encrypt\n$decrypt");
  }

  Future<void> aeadXchacha20poly1305() async {
    List encrypt = await AEADxChaCha20poly1305.encrypt(
        aad: aad,
        iv: iv,
        key: key,
        constant: constant,
        hNonce: hNonce,
        plaintext: plaintextWithoutPrefix);
    String decrypt = await AEADxChaCha20poly1305.decrypt(
        aad: aad,
        iv: iv,
        key: key,
        constant: constant,
        hNonce: hNonce,
        ciphertext: encrypt[0],
        savedTag: encrypt[1]);

    debugPrint("$encrypt\n$decrypt");
  }

  Future<void> xChaCha20() async {
    String encrypt = await XChaCha20.encrypt(
        key: key, nonce: hNonce, plaintext: plaintextWithoutPrefix);
    String decrypt =
        await XChaCha20.decrypt(key: key, nonce: hNonce, ciphertext: encrypt);

    debugPrint("$encrypt\n$decrypt");
  }

  aeadXchacha20poly1305prefix();
  xChaChaPrefix();
  aeadXchacha20poly1305();
  xChaCha20();
}
