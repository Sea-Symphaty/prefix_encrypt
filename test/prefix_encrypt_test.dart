import 'package:flutter/cupertino.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:prefix_encrypt/prefix_encrypt.dart';

void main() async {
  test('Encryptor test', () async {

    String key =
        "0000000000000000000000000000000000000000000000000000000000000000"; //must be 64 character
    String nonce =
        "000000000000000000000000000000000000000000000000"; //must be 48 character
    String plaintext = "Hello World!😄";
    String encrypt = await XChaCha20withPrefix.encrypt(
        key: key, nonce: nonce, plaintext: plaintext);

    debugPrint(encrypt);
  });
}
