import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:webrtc_rs/handshake_context.dart';
import 'package:x25519/x25519.dart';
import 'package:collection/collection.dart'; // For ListEquality
import 'dart:convert';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'handshake/server_key_exchange.dart';

void genKeyAndX25519() {
  var aliceKeyPair = generateKeyPair();
  var bobKeyPair = generateKeyPair();

  var aliceSharedKey = X25519(aliceKeyPair.privateKey, bobKeyPair.publicKey);
  var bobSharedKey = X25519(bobKeyPair.privateKey, aliceKeyPair.publicKey);

  assert(ListEquality().equals(aliceSharedKey, bobSharedKey));
}

Uint8List generateValueKeyMessage(Uint8List clientRandom,
    Uint8List serverRandom, Uint8List publicKey, ECCurveType curve) {
  //See signed_params enum: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3

  // logging.Descf(logging.ProtoCRYPTO,
  // 	common.JoinSlice("\n", false,
  // 		common.ProcessIndent("Generating plaintext of signed_params values consist of:", "+", []string{
  // 			fmt.Sprintf("Client Random <u>0x%x</u> (<u>%d bytes</u>)", clientRandom, len(clientRandom)),
  // 			fmt.Sprintf("Server Random <u>0x%x</u> (<u>%d bytes</u>)", serverRandom, len(serverRandom)),
  // 			common.ProcessIndent("ECDH Params:", "", []string{
  // 				fmt.Sprintf("[0]: <u>%s</u>\n[1:2]: <u>%s</u>\n[3]: <u>%d</u> (public key length)", CurveTypeNamedCurve, curve, len(publicKey)),
  // 			}),
  // 			fmt.Sprintf("Public Key: <u>0x%x</u>", publicKey),
  // 		})))
  ByteData serverECDHParams = ByteData(4);
  // serverECDHParams[0] = byte(CurveTypeNamedCurve)
  serverECDHParams.setUint8(0, curve.value);
  // binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(curve))
  serverECDHParams.setUint16(1, NamedCurve.X25519.value);
  // serverECDHParams[3] = byte(len(publicKey))
  serverECDHParams.setUint8(3, publicKey.length);

  final bb = BytesBuilder();
  bb.add(clientRandom);
  bb.add(serverRandom);
  bb.add(serverECDHParams.buffer.asUint8List());
  bb.add(publicKey);

  return bb.toBytes();
}

Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKeyBytes,
    ECCurveType curveValue,
    List<int> privateKeyBytes) async {
  // Generate the message to sign
  final msg = generateValueKeyMessage(
      clientRandom, serverRandom, publicKeyBytes, curveValue);

  // Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Convert private key bytes to Ed25519 private key
  final algorithm = cryptography.Ed25519();
  final privateKey = cryptography.SimpleKeyPairData(
    privateKeyBytes,
    publicKey: cryptography.SimplePublicKey(publicKeyBytes,
        type: cryptography.KeyPairType.ed25519),
    type: cryptography.KeyPairType.ed25519,
  );

  // Sign the hashed message
  final signature = await algorithm.sign(
    hashedMessage,
    keyPair: privateKey,
  );

  // Return the signature
  return Uint8List.fromList(signature.bytes);
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

Future<({Uint8List privateKey, Uint8List publicKey})>
    generateEd25519Keys() async {
  final algorithm = cryptography.Ed25519();

  // Generate key pair
  final keyPair = await algorithm.newKeyPair();
  final privateKey = await keyPair.extractPrivateKeyBytes();
  final publicKey = await keyPair.extractPublicKey();

  print('Private Key (Base64): ${base64Encode(privateKey)}');
  print('Public Key (Base64): ${base64Encode(publicKey.bytes)}');
  print('Private Key length: ${privateKey.length}');
  print('Public Key length: ${publicKey.bytes.length}');

  // Sign a message
  final message = utf8.encode('This is a test message.');
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair,
  );

  print('Signature: ${base64Encode(signature.bytes)}');
  return (
    privateKey: Uint8List.fromList(privateKey),
    publicKey: Uint8List.fromList(publicKey.bytes)
  );
}

void main() async {
  final algorithm = cryptography.Ed25519();

  // Generate key pair
  final keyPair = await algorithm.newKeyPair();
  final privateKey = await keyPair.extractPrivateKeyBytes();
  final publicKey = await keyPair.extractPublicKey();

  print('Private Key (Base64): ${base64Encode(privateKey)}');
  print('Public Key (Base64): ${base64Encode(publicKey.bytes)}');

  // Sign a message
  final message = utf8.encode('This is a test message.');
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair,
  );

  print('Signature: ${base64Encode(signature.bytes)}');
}
