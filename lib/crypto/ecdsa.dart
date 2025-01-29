import 'package:crypto/crypto.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'dart:typed_data';

import '../handshake/server_key_exchange.dart';

void main() {
  // var ec = getP256();
  // var priv = ec.generatePrivateKey();
  // var pub = priv.publicKey;
  // print(priv);
  // print(pub);
  // var hashHex =
  //     'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  // var hash = List<int>.generate(hashHex.length ~/ 2,
  //     (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
  // var sig = signature(priv, hash);

  // var result = verify(pub, hash, sig);
  // assert(result);

  generateECDSAkeys();
}

/// Encodes the public key in uncompressed format (0x04 || x || y)
Uint8List encodePublicKey(PublicKey pub) {
  // Convert x and y to 32-byte arrays with padding
  final xBytes = _bigIntToBytes(pub.X, 32);
  final yBytes = _bigIntToBytes(pub.Y, 32);

  // Prefix with 0x04 for uncompressed format
  return Uint8List.fromList([0x04, ...xBytes, ...yBytes]);
}

Uint8List encodeCompressedPublicKey(PublicKey pub) {
  // Convert x to a 32-byte array with padding
  final xBytes = _bigIntToBytes(pub.X, 32);

  // Determine the prefix (0x02 for even y, 0x03 for odd y)
  final prefix = pub.Y.isEven ? 0x02 : 0x03;

  // Combine prefix and x-coordinate
  return Uint8List.fromList([prefix, ...xBytes]);
}

/// Converts a BigInt to a fixed-length Uint8List with zero-padding
Uint8List _bigIntToBytes(BigInt value, int length) {
  // Convert BigInt to a byte list
  final byteArray =
      value.toUnsigned(256).toRadixString(16).padLeft(length * 2, '0');
  return Uint8List.fromList(List.generate(
    length,
    (i) => int.parse(byteArray.substring(i * 2, i * 2 + 2), radix: 16),
  ));
}

({Uint8List privateKey, Uint8List publicKey}) generateECDSAkeys() {
  // Step 1: Key Exchange (ECDHE)

  var ec = getP256();
  var priv = ec.generatePrivateKey();
  final serverPrivateKeyBytes = Uint8List.fromList(priv.bytes);

  final pub = priv.publicKey;

  // Extract the x-coordinate (32 bytes) from the public key
  var xCoordinate = pub.X;
  var xBytes =
      xCoordinate.toRadixString(16).padLeft(64, '0'); // 32 bytes (64 hex chars)
  //print("x-Coordinate (Hex): $xBytes");

  // Convert to Uint8List (32 bytes)
  var xBytesList = List<int>.generate(xBytes.length ~/ 2,
      (i) => int.parse(xBytes.substring(i * 2, i * 2 + 2), radix: 16));
  //print("x-Coordinate (Bytes): $xBytesList");

  final serverPublicKeyBytes = Uint8List.fromList(xBytesList);

  // Validate length
  //print("x-coordinate length must be 32 bytes: ${xBytesList.length == 32}");

  return (privateKey: serverPrivateKeyBytes, publicKey: serverPublicKeyBytes);
}

// import 'dart:convert';
// import 'package:crypto/crypto.dart';
// import 'package:ecdsa/ecdsa.dart';
// import 'package:elliptic/elliptic.dart';

Future<Uint8List> generateKeySignature(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKeyBytes,
  ECCurveType curveValue,
  List<int> privateKeyBytes,
) async {
  // Step 1: Generate the message to sign
  final message = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Step 2: Hash the message using SHA-256
  final hashedMessage = sha256.convert(message).bytes;

  // Step 3: Initialize elliptic curve and private key
  final curve = getP256(); // secp256r1 corresponds to P-256
  final privateKey = PrivateKey.fromBytes(curve, privateKeyBytes);

  // Step 4: Generate the signature
  final signatureData = signature(privateKey, hashedMessage);

  // Step 5: Combine the r and s values into a single byte array
  final rBytes = BigInt.parse(signatureData.R.toString())
      .toRadixString(16)
      .padLeft(64, '0');
  final sBytes = BigInt.parse(signatureData.S.toString())
      .toRadixString(16)
      .padLeft(64, '0');
  final signatureBytes = Uint8List.fromList([
    ..._bigIntToBytes(BigInt.parse(rBytes, radix: 16), 32),
    ..._bigIntToBytes(BigInt.parse(sBytes, radix: 16), 32),
  ]);

  return signatureBytes;
}

/// Example implementation of `generateValueKeyMessage`. Replace with your actual logic.
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
