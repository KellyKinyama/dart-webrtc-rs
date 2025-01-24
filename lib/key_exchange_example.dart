import 'dart:typed_data';

import 'package:x25519/x25519.dart';
import 'package:collection/collection.dart'; // For ListEquality

void genKeyAndX25519() {
  var aliceKeyPair = generateKeyPair();
  var bobKeyPair = generateKeyPair();

  var aliceSharedKey = X25519(aliceKeyPair.privateKey, bobKeyPair.publicKey);
  var bobSharedKey = X25519(bobKeyPair.privateKey, aliceKeyPair.publicKey);

  assert(ListEquality().equals(aliceSharedKey, bobSharedKey));
}

void useX25519() {
  const expectedHex =
      '89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a';
  var x = List<int>.filled(32, 0);
  x[0] = 1;

  for (var i = 0; i < 200; i++) {
    x = X25519(x, basePoint);
  }
  //assert(HEX.encode(x) == expectedHex);
  //print(x);
}

({Uint8List privateKey, Uint8List publicKey}) generateKeys() {
  final aliceKeyPair = generateKeyPair();
  final privKey = Uint8List.fromList(aliceKeyPair.privateKey);
  final pubKey = Uint8List.fromList(aliceKeyPair.publicKey);
  return (privateKey: privKey, publicKey: pubKey);
}
