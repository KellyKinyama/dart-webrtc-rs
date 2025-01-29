import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:crypto/crypto.dart';
import 'dart:math';

import '../handshake/server_key_exchange.dart';

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
  // Step 1: Generate the message to sign
  final message = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Step 2: Hash the message using SHA-256
  final hashedMessage = sha256.convert(message).bytes;

  // Step 3: Setup ECDSA with the secp256r1 curve
  final domainParams =
      ECDomainParameters('prime256v1'); // secp256r1 = prime256v1
  final privateKey = ECPrivateKey(
      BigInt.parse(privateKeyBytes.map((e) => e.toRadixString(16)).join(),
          radix: 16),
      domainParams);

  // Step 4: Initialize a secure random generator
  final secureRandom = _getSecureRandom();

  // Step 5: Initialize signer
  final signer = Signer('SHA-256/ECDSA')
    ..init(
      true, // true for signing
      PrivateKeyParameter<ECPrivateKey>(privateKey),
    );

  // Step 6: Generate the signature
  final signature = signer.generateSignature(Uint8List.fromList(hashedMessage))
      as ECSignature;

  // Step 7: Convert r and s values to bytes
  final rBytes = bigIntToBytes(signature.r);
  final sBytes = bigIntToBytes(signature.s);
  final signatureBytes = Uint8List.fromList([...rBytes, ...sBytes]);

  return signatureBytes;
}

/// Helper to create a SecureRandom instance
SecureRandom _getSecureRandom() {
  final secureRandom = FortunaRandom();
  final seed = Uint8List(32); // 32 bytes = 256 bits
  final random = Random.secure();
  for (var i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }
  secureRandom.seed(KeyParameter(seed));
  return secureRandom;
}

/// Helper to convert BigInt to bytes
Uint8List bigIntToBytes(BigInt number) {
  final byteMask = BigInt.from(0xFF);
  var temp = number;
  final bytes = <int>[];

  while (temp > BigInt.zero) {
    bytes.insert(0, (temp & byteMask).toInt());
    temp = temp >> 8;
  }

  // Ensure the byte length matches expectations (e.g., 32 bytes for secp256r1)
  while (bytes.length < 32) {
    bytes.insert(0, 0);
  }

  return Uint8List.fromList(bytes);
}
