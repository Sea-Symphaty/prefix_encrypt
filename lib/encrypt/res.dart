import 'dart:math';

String serialize(String hex) {
  /// Here the hexadecimal value is first checked if it has 8 digits, if not a 0 is added in front and then rotated.
  String newHex = isNotEven(hex);
  List list = [
    for (int a = hex.length; a > 0; a -= 2) newHex.substring(a - 2, a)
  ];
  String hexTurn = list.join();

  return hexTurn;
}

String isNotEven(String string) {
  /// If the hexadecimal digits are odd because the 0 is omitted, then one is added. Because when merging the values, the zero is also important.
  if (!string.length.isEven) {
    string = "0$string";
  }
  return string;
}

List stringHexToListHex(String string) {
  /// The string is divided into 8 byte long parts and added to a list. If the rest of the string is not long enough, then only the parts that are
  /// available are taken.
  List list = [];

  for (int a = 0; a < string.length; a += 8) {
    String hex = "";
    if (string.length - a < 8) {
      hex = string.substring(a, string.length);
    } else {
      hex = string.substring(a, a + 8);
    }

    list.add(hex);
  }

  return list;
}

int leftRoll(int value, int count) {
  /// The count value specifies by how many places the hexadecimal value is shifted in bits.
  /// For example: Value: 1100 0011, count 5. 1.Round: 1000 0111, 2.Round: 0000 1111, 3.Round: 0001 1110, 4.Round: 0011 1100, 5.Round: 0111 1000
  /// Result: 0111 1000
  String valueBit = value.toRadixString(2);
  if (valueBit.length < 32) {
    /// as long as the size of the value does not have 32 bits, a 0 is always introduced.
    while (valueBit.length < 32) {
      valueBit = "0$valueBit";
    }
  }

  String firstBit = valueBit.substring(0, count);
  String lastBit = valueBit.substring(count, valueBit.length);

  return int.parse(lastBit + firstBit, radix: 2);

  /// The last bits are placed after the first bits and converted to int again
}

List bigIntHexList(List listHex) {
  /// The list with the individual hexadecimal characters is merged and then divided into 128 characters. After that the single parts
  /// are converted to BigInt.
  String stringHex = "";
  List list = [];
  for (int a = 0; a < listHex.length; a++) {
    listHex[a] = isNotEven(listHex[a]);
    stringHex += listHex[a];
  }
  list = stringHexTo128HexList(stringHex);

  return [
    for (int a = 0; a < list.length; a++) BigInt.parse(list[a], radix: 16)
  ];
}

List stringHexTo128HexList(String stringHex) {
  /// The compound string is separated into 128 characters and added to a list. So that the plaintext can be offset with the block using XOR.
  List list = [];
  for (int a = 0; a < stringHex.length; a++) {
    int maxLength = ((a + 1) * 128);
    String string128 = "";

    if (maxLength > stringHex.length) {
      string128 = stringHex.substring(a * 128, stringHex.length);
    } else {
      string128 = stringHex.substring(a * 128, maxLength);
    }
    string128 = isNotEven(string128);
    list.add(string128);

    if (maxLength >= stringHex.length) {
      break;
    }
  }
  return list;
}

List stringTextToListHex(String string) {
  /// The plaintext is converted to hexadecimal and then divided into large parts in BigInt.
  List listDec = string.runes.toList();
  List listHex = [
    for (int a = 0; a < listDec.length; a++) listDec[a].toRadixString(16)
  ];

  return bigIntHexList(listHex);
}

List stringTextToListHexPrefix(String string) {
  List listDec = string.runes.toList();
  List listHex = [];
  int symbol6Hex = 0;
  int textLength = 2;
  int prefixLength = 0;

  for (int a = 0; a < listDec.length; a++) {
    String stringHex = listDec[a].toRadixString(16);
    stringHex = isNotEven(stringHex);
    if (stringHex.length > 3) {
      /// If the hexadecimal value is more than three characters long, the following happens: First the prefix is created. For this the current counter
      /// of the loop is added with textlength and then multiplied by 2, because decryption is done in single bytes. The number 1 and 2 indicate how
      /// long the hexadecimal value is. Second we add the prefix to the first position or after the last prefix. Then the length of the prefix is
      /// added to the current value, the textLength is increased by 1 or 2 depending on how long the symbol is, and finally the counter for the
      /// six-digit hexadecimal values is increased if this was one.
      List prefixList =
          prefixInt((a + textLength) * 2, stringHex.length == 4 ? 1 : 2);
      listHex.insertAll(prefixLength, prefixList);

      prefixLength += prefixList.length;
      textLength += stringHex.length == 4 ? 1 : 2;
      symbol6Hex += stringHex.length == 4 ? 0 : 1;
    }

    listHex.add(stringHex);
  }

  List prefixTextLength = prefixInt(listDec.length + symbol6Hex, 0);

  /// First the length of the text is added.
  listHex.insertAll(0, prefixTextLength);

  /// The semicolon is inserted so that you know where the last symbol is when decoding.
  listHex.insert(prefixLength + prefixTextLength.length, "3b");
  return bigIntHexList(listHex);
}

List prefixInt(int length, int hexLength) {
  /// The length for the text or the position of the symbol is converted to hexadecimal and then a colon (0x3a) is added. If hexLength is 1, then a 4
  /// is added or if hexLength is 2, then a 6 is added. The numbers represent the length of the hexadecimal values.
  List codeUnits = length.toString().codeUnits;
  List lengthList = [
    for (int a = 0; a < codeUnits.length; a++) codeUnits[a].toRadixString(16),
    "3a"
  ];

  if (hexLength == 1) {
    lengthList.insertAll(lengthList.length - 1, ["2e", "34"]);
  } else if (hexLength == 2) {
    lengthList.insertAll(lengthList.length - 1, ["2e", "36"]);
  }

  return lengthList;
}

String padding32Bytes(String hex) {
  /// The hex must be divisible by 32 without remainder. If this is not the case, then zeros are inserted to the right until the value is divisible by
  /// 32. This is important for the Poly1305 because it consists of four elements of a block.
  if (hex.length % 32 != 0) {
    hex = hex.padRight(32 * (hex.length / 32).ceil(), "0");
  }

  return hex;
}

String lengthTo16Bytes(int length) {
  /// The hex must be divisible by 16 without remainder. If this is not the case, then zeros are inserted to the right until the value is divisible by
  /// 16. This is important for the Poly1305 because it consists of four elements of a block.
  String lengthHex =
      int.parse((length / 2).toStringAsFixed(0)).toRadixString(16);
  lengthHex = isNotEven(lengthHex);
  if ((lengthHex.length % 16) != 0) {
    lengthHex = lengthHex.padRight(16 * (lengthHex.length / 16).ceil(), "0");
  }

  return lengthHex;
}

void quarterRound(List list, int x, int y, int z, int w) {
  num mod = pow(2, 32); // 2^32
  var a = list[x];
  var b = list[y];
  var c = list[z];
  var d = list[w];

  a = (a + b) % mod;
  d = leftRoll(d ^ a, 16);
  c = (c + d) % mod;
  b = leftRoll(b ^ c, 12);
  a = (a + b) % mod;
  d = leftRoll(d ^ a, 8);
  c = (c + d) % mod;
  b = leftRoll(b ^ c, 7);

  list[x] = a;
  list[y] = b;
  list[z] = c;
  list[w] = d;
}

void innerBlock(block) {
  /// The first four quarterRounds are columns, i.e. horizontal passes, and the last four are diagonal passes. After a complete pass, each element
  /// was encoded twice.
  quarterRound(block, 0, 4, 8, 12);
  quarterRound(block, 1, 5, 9, 13);
  quarterRound(block, 2, 6, 10, 14);
  quarterRound(block, 3, 7, 11, 15);
  quarterRound(block, 0, 5, 10, 15);
  quarterRound(block, 1, 6, 11, 12);
  quarterRound(block, 2, 7, 8, 13);
  quarterRound(block, 3, 4, 9, 14);
}
