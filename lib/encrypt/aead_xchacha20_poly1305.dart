import 'poly1305.dart';
import 'res.dart';
import 'xchacha20.dart';

/// With AEAD XChaCha20 Poly1305, regardless whether with or without prefix, the plaintext is first encrypted with XChaCha20. From constants and the iv
/// (Initialization Vector) the nonce for the one time key is created. An onetimekey for Poly1305 is created from the nonce and the secret key.
/// The information for the MAC is created as follows: The AAD is incremented to a length divisible by 32, the Encrypted Text is incremented to a length
/// divisible by 32, the length of the original AAD is converted to hexadecimal and the length is incremented until it is divisible by 16, the length of
/// the original Encrypted Text is converted to hexadecimal and incremented to a length until it is divisible by 16. These four values and the onetimekey
/// are used to create a tag.
/// During decryption, a tag is also created and compared with the tag from encryption. If this should deviate, then this is regarded as wrong and/or
/// manipulated, since with the same values also the same tag must be computed.

class AEADxChaCha20poly1305withPrefix {
  static Future<List<String>> encrypt(
      {required String aad,
      required String iv,
      required String key,
      required String constant,
      required String hNonce,
      required String plaintext}) async {
    if (aad.isEmpty) {
      throw ("AEAD XChaCha20 Poly1305 with prefix encrypt\nAAD must be at least 1 character.");
    } else if (iv.length < 16) {
      throw ("AEAD XChaCha20 Poly1305 with prefix encrypt\nIV must be at least 16 character.");
    } else if (key.length != 64) {
      throw ("AEAD XChaCha20 Poly1305 with prefix encrypt\nKey must be 64 character.");
    } else if (constant.length != 8) {
      throw ("AEAD XChaCha20 Poly1305 with prefix encrypt\nConstant must be 8 character.");
    } else if (hNonce.length != 48) {
      throw ("AEAD XChaCha20 Poly1305 with prefix encrypt\nhNonce must be 48 character.");
    } else {
      String nonce = constant + iv;
      String oneTimeKey = Poly1305.keyGen(key, nonce);
      String ciphertext = await XChaCha20withPrefix.encrypt(
          key: key, nonce: hNonce, plaintext: plaintext);
      String macData = padding32Bytes(aad) +
          padding32Bytes(ciphertext) +
          lengthTo16Bytes(aad.length) +
          lengthTo16Bytes(ciphertext.length);
      String tag = Poly1305.mac(macData, oneTimeKey);
      return [ciphertext, tag];
    }
  }

  static Future<String> decrypt(
      {required String aad,
      required String iv,
      required String key,
      required String constant,
      required String hNonce,
      required String ciphertext,
      required String savedTag}) async {
    if (aad.isEmpty) {
      throw ("AEAD XChaCha20 Poly1305 with prefix decrypt\nAAD must be at least 1 character.");
    } else if (iv.length < 16) {
      throw ("AEAD XChaCha20 Poly1305 with prefix decrypt\nIV must be at least 16 character.");
    } else if (key.length != 64) {
      throw ("AEAD XChaCha20 Poly1305 with prefix decrypt\nKey must be 64 character.");
    } else if (constant.length != 8) {
      throw ("AEAD XChaCha20 Poly1305 with prefix decrypt\nConstant must be 8 character.");
    } else if (hNonce.length != 48) {
      throw ("AEAD XChaCha20 Poly1305 with prefix decrypt\nhNonce must be 48 character.");
    } else {
      String nonce = constant + iv;
      String oneTimeKey = Poly1305.keyGen(key, nonce);
      String macData = padding32Bytes(aad) +
          padding32Bytes(ciphertext) +
          lengthTo16Bytes(aad.length) +
          lengthTo16Bytes(ciphertext.length);
      String tag = Poly1305.mac(macData, oneTimeKey);

      if (tag == savedTag) {
        return XChaCha20withPrefix.decrypt(
            key: key, nonce: hNonce, ciphertext: ciphertext);
      } else {
        throw "Tag doesn't match";
      }
    }
  }
}

class AEADxChaCha20poly1305 {
  static Future<List<String>> encrypt(
      {required String aad,
      required String iv,
      required String key,
      required String constant,
      required String hNonce,
      required String plaintext}) async {
    if (aad.isEmpty) {
      throw ("AEAD XChaCha20 Poly1305 encrypt\nAAD must be at least 1 character.");
    } else if (iv.length < 16) {
      throw ("AEAD XChaCha20 Poly1305 encrypt\nIV must be at least 16 character.");
    } else if (key.length != 64) {
      throw ("AEAD XChaCha20 Poly1305 encrypt\nKey must be 64 character.");
    } else if (constant.length != 8) {
      throw ("AEAD XChaCha20 Poly1305 encrypt\nConstant must be 8 character.");
    } else if (hNonce.length != 48) {
      throw ("AEAD XChaCha20 Poly1305 encrypt\nhNonce must be 48 character.");
    } else {
      String nonce = constant + iv;
      String oneTimeKey = Poly1305.keyGen(key, nonce);
      String ciphertext = await XChaCha20.encrypt(
          key: key, nonce: hNonce, plaintext: plaintext);
      String macData = padding32Bytes(aad) +
          padding32Bytes(ciphertext) +
          lengthTo16Bytes(aad.length) +
          lengthTo16Bytes(ciphertext.length);
      String tag = Poly1305.mac(macData, oneTimeKey);
      return [ciphertext, tag];
    }
  }

  static Future<String> decrypt(
      {required String aad,
      required String iv,
      required String key,
      required String constant,
      required String hNonce,
      required String ciphertext,
      required String savedTag}) async {
    if (aad.isEmpty) {
      throw ("AEAD XChaCha20 Poly1305 decrypt\nAAD must be at least 1 character.");
    } else if (iv.length < 16) {
      throw ("AEAD XChaCha20 Poly1305 decrypt\nIV must be at least 16 character.");
    } else if (key.length != 64) {
      throw ("AEAD XChaCha20 Poly1305 decrypt\nKey must be 64 character.");
    } else if (constant.length != 8) {
      throw ("AEAD XChaCha20 Poly1305 decrypt\nConstant must be 8 character.");
    } else if (hNonce.length != 48) {
      throw ("AEAD XChaCha20 Poly1305 decrypt\nhNonce must be 48 character.");
    } else {
      String nonce = constant + iv;
      String oneTimeKey = Poly1305.keyGen(key, nonce);
      String macData = padding32Bytes(aad) +
          padding32Bytes(ciphertext) +
          lengthTo16Bytes(aad.length) +
          lengthTo16Bytes(ciphertext.length);
      String tag = Poly1305.mac(macData, oneTimeKey);

      if (tag == savedTag) {
        return XChaCha20.decrypt(
            key: key, nonce: hNonce, ciphertext: ciphertext);
      } else {
        throw "Tag doesn't match";
      }
    }
  }
}
