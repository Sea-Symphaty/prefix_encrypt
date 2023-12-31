# Overview
[![GitHub](https://img.shields.io/badge/GitHub-prefix_encrypt-gre.svg?logo=github&color=2ea44f)](https://github.com/Sea-Symphaty/prefix_encrypt) [![Pub](https://img.shields.io/pub/v/prefix_encrypt.svg?logo=dart&color=2ea44f)](https://pub.dev/packages/prefix_encrypt)


This dart package allows easy encryption of text using AEAD XChaCha20 Poly1305 and XChaCha20, also including a prefix in the encrypted text for symbols that have over a decimal value of 255 in the ASCII table. So that these are decrypted correctly.

Example:
```dart
import 'package:flutter/cupertino.dart';
import 'package:prefix_encrypt/prefix_encrypt.dart';

void main() async {
  // all values have to be in hexadecimal

  String key = "0000000000000000000000000000000000000000000000000000000000000000"; //must be 64 character
  String nonce = "000000000000000000000000000000000000000000000000"; //must be 48 character
  String plaintext = "Hello World!😄";
  String encrypt = await XChaCha20withPrefix.encrypt(key: key, nonce: nonce, plaintext: plaintext);

  debugPrint(encrypt);
  // Output "49aaacbbdd0ebb45e2a996a9d95b3f1f806acd5a60886ea9"
  // Decrypted text: "Hello World!😄"
  // Decrypted text with prefix: 14:28.6:;Hello World!😄
}
```
Since decoding is always done in two pairs, the symbols with more than two hexadecimal digits are also divided into two pairs. For example, 💚(01F49A) becomes 01 F4 9A. To prevent this, a prefix is added at the beginning of the text, after the length of the text, indicating where the symbol is and how many digits it has. For example: "28.6:". The first number is for the digit and the second for the length of the symbol in hex. If there are no more symbols or there are none, the prefix is ended with a semicolon.
The algorithm for AEAD XChaCha20 Poly1305 and XChaCha is from the site: [https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03) and [https://www.rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439).
