import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'package:x25519/x25519.dart' as x25519;

import '../handshake/server_key_exchange.dart';

({Uint8List privateKey, Uint8List publicKey}) generateKeys() {
  final aliceKeyPair = x25519.generateKeyPair();
  final privKey = Uint8List.fromList(aliceKeyPair.privateKey);
  final pubKey = Uint8List.fromList(aliceKeyPair.publicKey);
  return (privateKey: privKey, publicKey: pubKey);
}

Future<({Uint8List privateKey, Uint8List publicKey})>
    generateEd25519Keys() async {
  final algorithm = cryptography.Ed25519();
  final keyPair = await algorithm.newKeyPair();
  final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
  final publicKey = await keyPair.extractPublicKey();
  return (
    privateKey: Uint8List.fromList(privateKeyBytes),
    publicKey: Uint8List.fromList(publicKey.bytes)
  );
}

Uint8List generateValueKeyMessage(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKey,
  ECCurveType curve,
) {
  ByteData serverECDHParams = ByteData(4);
  serverECDHParams.setUint8(0, curve.value); // Curve type
  serverECDHParams.setUint16(1, NamedCurve.X25519.value); // Curve ID
  serverECDHParams.setUint8(3, publicKey.length); // Public key length

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
  List<int> privateKeyBytes,
) async {
  // Generate the message to sign
  final msg = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Convert the private key bytes to an Ed25519 private key
  final privateKey = cryptography.SimpleKeyPairData(
    privateKeyBytes,
    publicKey: cryptography.SimplePublicKey(publicKeyBytes,
        type: cryptography.KeyPairType.ed25519),
    type: cryptography.KeyPairType.ed25519,
  );

  // Use Ed25519 to sign the hashed message
  final algorithm = cryptography.Ed25519();
  final signature = await algorithm.sign(hashedMessage, keyPair: privateKey);

  // Return the signature as Uint8List
  return Uint8List.fromList(signature.bytes);
}

Future<bool> verifyKeySignature(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKeyBytes,
  ECCurveType curveValue,
  Uint8List signatureBytes,
) async {
  // Generate the message to verify
  final msg = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Convert the public key bytes to an Ed25519 public key object
  final publicKey = cryptography.SimplePublicKey(
    publicKeyBytes,
    type: cryptography.KeyPairType.ed25519,
  );

  // Verify the signature
  final algorithm = cryptography.Ed25519();
  return await algorithm.verify(
    hashedMessage,
    signature: cryptography.Signature(signatureBytes, publicKey: publicKey),
  );
}

void main() async {
  // Example inputs
  final clientRandom = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final serverRandom = Uint8List.fromList([9, 10, 11, 12, 13, 14, 15, 16]);
  final keys = await generateEd25519Keys();
  final publicKeyBytes = keys.publicKey;
  final privateKeyBytes = keys.privateKey;
  final curveValue = ECCurveType.fromInt(0x03); // Example curve type value

  // Generate a signature
  final algorithm = cryptography.Ed25519();
  final privateKey = cryptography.SimpleKeyPairData(
    privateKeyBytes,
    publicKey: cryptography.SimplePublicKey(publicKeyBytes,
        type: cryptography.KeyPairType.ed25519),
    type: cryptography.KeyPairType.ed25519,
  );

  final msg = generateValueKeyMessage(
      clientRandom, serverRandom, publicKeyBytes, curveValue);
  final hashedMessage = sha256.convert(msg).bytes;
  final signature = await algorithm.sign(hashedMessage, keyPair: privateKey);

  // Verify the signature
  final isValid = await verifyKeySignature(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
    Uint8List.fromList(signature.bytes),
  );

  if (isValid) {
    print('Signature is valid!');
  } else {
    print('Signature is invalid!');
  }
}

void generateKeySignatureExample() async {
  // Example inputs
  final clientRandom = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final serverRandom = Uint8List.fromList([9, 10, 11, 12, 13, 14, 15, 16]);

  // Generate Ed25519 key pair
  final keys = await generateEd25519Keys();
  final publicKeyBytes = keys.publicKey;
  final privateKeyBytes = keys.privateKey;

  final curveValue =
      ECCurveType.fromInt(0x03); // Placeholder curve value for Ed25519

  // Generate the signature
  final signature = await generateKeySignature(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
    privateKeyBytes,
  );

  // Output the signature
  print('Generated Signature: ${signature.toString()}');
}
