import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';

import '../handshake/server_key_exchange.dart';

Future<void> main() async {
  // Step 1: Key Exchange (ECDHE)
  final ecdh = X25519(); // You can also use P-256 (secp256r1) with ECDH.
  final clientKeyPair = await ecdh.newKeyPair();
  final serverKeyPair = await ecdh.newKeyPair();

  // Exchange public keys
  final clientPublicKey = await clientKeyPair.extractPublicKey();
  final serverPublicKey = await serverKeyPair.extractPublicKey();

  // Derive shared secrets
  final clientSharedSecret = await ecdh.sharedSecretKey(
    keyPair: clientKeyPair,
    remotePublicKey: serverPublicKey,
  );

  final serverSharedSecret = await ecdh.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );

  // Confirm shared secret matches
  final clientSharedSecretBytes = await clientSharedSecret.extractBytes();
  final serverSharedSecretBytes = await serverSharedSecret.extractBytes();
  print('Client Shared Secret: ${base64Encode(clientSharedSecretBytes)}');
  print('Server Shared Secret: ${base64Encode(serverSharedSecretBytes)}');
  assert(base64Encode(clientSharedSecretBytes) ==
      base64Encode(serverSharedSecretBytes));

  // Step 2: Authentication (ECDSA)
  final ecdsa = Ed25519(); // Replace with an ECDSA implementation if needed.
  final serverSigningKeyPair = await ecdsa.newKeyPair();

  // Sign data (e.g., handshake message) using ECDSA
  final message = utf8.encode('Handshake Message');
  final serverSignature = await ecdsa.sign(
    message,
    keyPair: serverSigningKeyPair,
  );

  // Verify the signature
  final isVerified = await ecdsa.verify(
    message,
    signature: serverSignature,
  );

  print('Server Signature Verified: $isVerified');

  // Step 3: Encrypt and Decrypt using AES-128-GCM
  final aesGcm = AesGcm.with128bits();
  final encryptionKey = await clientSharedSecret.extract();
  final nonce =
      Uint8List(12); // GCM nonce (12 bytes, must be unique per encryption)
  final plaintext = utf8.encode('This is a secret message');

  // Encrypt the message
  final secretBox = await aesGcm.encrypt(
    plaintext,
    secretKey: encryptionKey,
    nonce: nonce,
  );

  print('Encrypted Message: ${base64Encode(secretBox.cipherText)}');

  // Decrypt the message
  final decryptedMessage = await aesGcm.decrypt(
    secretBox,
    secretKey: encryptionKey,
  );

  print('Decrypted Message: ${utf8.decode(decryptedMessage)}');
}

Future<({Uint8List privateKey, Uint8List publicKey})>
    generateECDSAkeys() async {
  // Step 1: Key Exchange (ECDHE)
  final ecdh = X25519(); // You can also use P-256 (secp256r1) with ECDH.
  //final clientKeyPair = await ecdh.newKeyPair();
  final serverKeyPair = await ecdh.newKeyPair();

  // Exchange public keys
  //final clientPublicKey = await clientKeyPair.extractPublicKey();
  final serverPublicKey = await serverKeyPair.extractPublicKey();
  final serverPrivateKey = await serverKeyPair.extractPrivateKeyBytes();
  final serverPrivateKeyBytes = Uint8List.fromList(serverPrivateKey);
  final serverPublicKeyBytes = Uint8List.fromList(serverPublicKey.bytes);

  return (privateKey: serverPrivateKeyBytes, publicKey: serverPublicKeyBytes);
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

/// Generates a digital signature using ECDSA with SHA-256.
Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKeyBytes,
    ECCurveType curveValue,
    List<int> privateKeyBytes) async {
  // Step 1: Generate the message to sign
  final msg = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Step 2: Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Step 3: Convert private key bytes to an ECDSA private key
  final ecdsaAlgorithm = Ecdsa.p256(Sha256());
  final privateKey = SimpleKeyPairData(
    privateKeyBytes,
    publicKey: SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.p256,
    ),
    type: KeyPairType.p256,
  );

  // Step 4: Sign the hashed message using ECDSA
  final signature = await ecdsaAlgorithm.sign(
    hashedMessage,
    keyPair: privateKey,
  );

  // Step 5: Return the signature bytes
  return Uint8List.fromList(signature.bytes);
}
