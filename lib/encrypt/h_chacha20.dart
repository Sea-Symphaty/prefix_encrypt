import 'res.dart';

/// The HChaCha20 block is created in the same way as the ChaCha20 block, except that it has no block counter. The nonce is instead 32 bytes long and
/// not 24 bytes as in ChaCha20.
String hChaCha20block(List key, List nonce) {
  List block = key + nonce;
  List tempList = [];

  block = [for (int a = 0; a < 12; a++) serialize(block[a])];
  block.insertAll(
      0, ["61707865", "3320646e", "79622d32", "6b206574"]); // Konstante
  block = [for (int a = 0; a < 16; a++) int.parse(block[a], radix: 16)];

  for (var i = 0; i < 10; i++) {
    innerBlock(block);
  }

  block = [
    for (int a = 0; a < 16; a++)
      serialize(isNotEven(block[a].toRadixString(16)))
  ];
  tempList.addAll(block.sublist(0, 4));
  tempList.addAll(block.sublist(12, 16));

  return tempList.join();
}
