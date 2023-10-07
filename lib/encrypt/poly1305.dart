import 'res.dart';
import 'chacha20_prefix.dart';

/// This is where the Poly1305 MAC algorithm is created.
class Poly1305 {
  static String mac(String macData, String oneTimeKey) {
    String clamp(List rList) {
      /// Decimal numbers are derived from the list of hexadecimal values, from the first part of the password (r), so that they can be calculated
      /// with AND. At the end these are converted back to hexadecimal, with an even number, then these are connected to a hexadecimal value
      /// and then rotated.
      List r = [for (int a = 0; a < 16; a++) int.parse(rList[a], radix: 16)];
      List rTemp = [];

      r[3] &= 15;
      r[7] &= 15;
      r[11] &= 15;
      r[15] &= 15;
      r[4] &= 252;
      r[8] &= 252;
      r[12] &= 252;

      rTemp = [for (int a = 0; a < 16; a++) isNotEven(r[a].toRadixString(16))];

      return serialize(rTemp.join());
    }

    String tag = "";
    List messageBlock = [];

    /// It splits the hexadecimal text into 32 bytes elements, rotates it, adds a "01" and then adds it to the list.
    for (int a = 0; a < macData.length; a += 32) {
      String string = "";
      if (a + 16 > macData.length) {
        string = "01${serialize(macData.substring(a, macData.length))}";
      } else {
        string = "01${serialize(macData.substring(a, a + 32))}";
      }
      messageBlock.add(string);
    }

    /// The first part of the key (32 bytes) is split into two groups in hexadecimal and then a BigInt is created with the clamp function.
    List rList = [
      for (int a = 0; a < 32; a += 2) oneTimeKey.substring(a, a + 2)
    ];
    BigInt r = BigInt.parse(clamp(rList), radix: 16);

    /// The second part of the key (32 bytes) is rotated and then also converted to BigInt.
    BigInt s = BigInt.parse(serialize(oneTimeKey.substring(32)), radix: 16);
    BigInt p = BigInt.parse("3fffffffffffffffffffffffffffffffb", radix: 16);
    BigInt accumulator = BigInt.from(0);

    /// The accumulator is then created here.
    for (int a = 0; a < messageBlock.length; a++) {
      /// The accumulator is added to the block element of the text. In the second step the accumulator is multiplied by r (first part of the key) and
      /// modulo is applied to it by p. At the first round the accumulator is still zero, but if there are more elements, then at the next round of
      /// calculation the accumulator will have the last value and so on.
      accumulator += BigInt.parse(messageBlock[a], radix: 16);
      accumulator = (accumulator * r) % p;
    }

    /// Now the accumulator must be added with s (second part of the key). If the result in hexadecimal has more than 32 digits, then the first ones
    /// are removed until there are only 32 characters left. The result is the tag.
    accumulator += s;

    if (accumulator.toRadixString(16).length > 32) {
      tag = accumulator.toRadixString(16);
      tag = serialize(tag.substring(tag.length - 32, tag.length));
    } else {
      tag = serialize(accumulator.toRadixString(16));
    }

    return tag;
  }

  /// Using the ChaCha20 block, a 64 character hexadecimal string is created. This will then serve as the key for the tag creation.
  static String keyGen(String key, String nonce) {
    String block =
        chacha20block(stringHexToListHex(key), 0, stringHexToListHex(nonce))
            .toRadixString(16);

    return block.substring(0, 64);
  }
}
