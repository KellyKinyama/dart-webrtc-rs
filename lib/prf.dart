import 'dart:typed_data';
import 'package:crypto/crypto.dart'; // For SHA256 and HMAC
import 'package:pointycastle/export.dart'; // For elliptic curve operations
import 'dart:convert';

import 'package:x25519/x25519.dart';

// Placeholder for CipherSuiteHash
enum CipherSuiteHash { sha256, sha384 }

List<int> hmacSha256(List<int> key, List<int> data) {
  final hmac = Hmac(sha256, key); // Using SHA256
  return hmac.convert(data).bytes;
}

// Helper function to perform the elliptic curve key exchange
List<int> ellipticCurvePreMasterSecret(
    List<int> publicKey, List<int> privateKey) {
  // Perform Diffie-Hellman key exchange using X25519
  return X25519(privateKey, publicKey);
}

List<int> prfPHash(List<int> secret, List<int> seed, int requestedLength) {
  List<int> lastRound = List.from(seed);
  List<int> out = [];
  final iterations =
      (requestedLength / 32).ceil(); // 32 is the output length of SHA-256

  for (int i = 0; i < iterations; i++) {
    lastRound = hmacSha256(secret, lastRound);
    List<int> lastRoundSeed = List.from(lastRound)..addAll(seed);
    List<int> withSecret = hmacSha256(secret, lastRoundSeed);
    out.addAll(withSecret);
  }

  return out.sublist(0, requestedLength);
}

class EncryptionKeys {
  final List<int> masterSecret;
  final List<int> clientMacKey;
  final List<int> serverMacKey;
  final List<int> clientWriteKey;
  final List<int> serverWriteKey;
  final List<int> clientWriteIv;
  final List<int> serverWriteIv;

  EncryptionKeys({
    required this.masterSecret,
    required this.clientMacKey,
    required this.serverMacKey,
    required this.clientWriteKey,
    required this.serverWriteKey,
    required this.clientWriteIv,
    required this.serverWriteIv,
  });
}

EncryptionKeys prfEncryptionKeys(List<int> masterSecret, List<int> clientRandom,
    List<int> serverRandom, int prfMacLen, int prfKeyLen, int prfIvLen) {
  List<int> seed = utf8.encode("key expansion") + serverRandom + clientRandom;
  List<int> material = prfPHash(
      masterSecret, seed, (2 * prfMacLen) + (2 * prfKeyLen) + (2 * prfIvLen));

  List<int> keyMaterial = List.from(material);

  List<int> clientMacKey = keyMaterial.sublist(0, prfMacLen);
  keyMaterial = keyMaterial.sublist(prfMacLen);

  List<int> serverMacKey = keyMaterial.sublist(0, prfMacLen);
  keyMaterial = keyMaterial.sublist(prfMacLen);

  List<int> clientWriteKey = keyMaterial.sublist(0, prfKeyLen);
  keyMaterial = keyMaterial.sublist(prfKeyLen);

  List<int> serverWriteKey = keyMaterial.sublist(0, prfKeyLen);
  keyMaterial = keyMaterial.sublist(prfKeyLen);

  List<int> clientWriteIv = keyMaterial.sublist(0, prfIvLen);
  keyMaterial = keyMaterial.sublist(prfIvLen);

  List<int> serverWriteIv = keyMaterial.sublist(0, prfIvLen);

  return EncryptionKeys(
    masterSecret: masterSecret,
    clientMacKey: clientMacKey,
    serverMacKey: serverMacKey,
    clientWriteKey: clientWriteKey,
    serverWriteKey: serverWriteKey,
    clientWriteIv: clientWriteIv,
    serverWriteIv: serverWriteIv,
  );
}

void main() {
  List<int> secret = utf8.encode("some secret");
  List<int> seed = utf8.encode("seed data");
  int requestedLength = 64;

  // Example usage of HMAC and PRF
  List<int> expandedKeys = prfPHash(secret, seed, requestedLength);
  print(expandedKeys);
}

List<int> prfPskPreMasterSecret(List<int> psk) {
  int pskLen = psk.length;

  // Create a byte list with size 2 (for the first uint16) + pskLen + 2 (for the second uint16)
  List<int> out = List<int>.filled(2 + pskLen + 2, 0);

  // Convert pskLen to big-endian format and store it at the beginning and after the psk
  out.setRange(0, 2, _toBigEndianUint16(pskLen));
  out.setRange(2 + pskLen, 2 + pskLen + 2, _toBigEndianUint16(pskLen));

  // Append the PSK itself
  out.setRange(2, 2 + pskLen, psk);

  return out;
}

// Helper function to convert an integer to a 2-byte list in big-endian order
List<int> _toBigEndianUint16(int value) {
  return [
    (value >> 8) & 0xFF, // High byte
    value & 0xFF // Low byte
  ];
}

List<int> prfPreMasterSecret(
    Uint8List publicKey, Uint8List privateKey, int curve) {
  switch (curve) {
    default:
      return ellipticCurvePreMasterSecret(publicKey, privateKey);
  }
}

List<int> prfExtendedMasterSecret(
  List<int> preMasterSecret,
  List<int> sessionHash,
  CipherSuiteHash hashType,
) {
  // The label for the extended master secret
  final String label = 'extended master secret';
  List<int> seed = utf8.encode(label) + sessionHash;

  // return prfPHash(preMasterSecret, seed, 48, hashType);
  return prfPHash(preMasterSecret, seed, 48);
}

List<int> prfMasterSecret(
  List<int> preMasterSecret,
  List<int> clientRandom,
  List<int> serverRandom,
  CipherSuiteHash hashType,
) {
  // The label for the master secret
  final String label = 'master secret';
  List<int> seed = utf8.encode(label) + clientRandom + serverRandom;

  // return prfPHash(preMasterSecret, seed, 48, hashType);

  return prfPHash(preMasterSecret, seed, 48);
}
