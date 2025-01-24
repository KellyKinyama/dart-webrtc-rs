import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';

import 'package:x25519/x25519.dart';

//import 'package:hmac/hmac.dart';

// CipherSuiteHash enum (just a placeholder for now)
enum CipherSuiteHash { sha256 }

// EncryptionKeys class
class EncryptionKeys {
  List<int> masterSecret;
  List<int> clientMacKey;
  List<int> serverMacKey;
  List<int> clientWriteKey;
  List<int> serverWriteKey;
  List<int> clientWriteIv;
  List<int> serverWriteIv;

  EncryptionKeys({
    required this.masterSecret,
    required this.clientMacKey,
    required this.serverMacKey,
    required this.clientWriteKey,
    required this.serverWriteKey,
    required this.clientWriteIv,
    required this.serverWriteIv,
  });

  @override
  String toString() {
    return 'EncryptionKeys:\n'
        '- master_secret: $masterSecret\n'
        '- client_mac_key: $clientMacKey\n'
        '- server_mac_key: $serverMacKey\n'
        '- client_write_key: $clientWriteKey\n'
        '- server_write_key: $serverWriteKey\n'
        '- client_write_iv: $clientWriteIv\n'
        '- server_write_iv: $serverWriteIv\n';
  }
}

// Constants for the PRF labels
const String PRF_MASTER_SECRET_LABEL = "master secret";
const String PRF_EXTENDED_MASTER_SECRET_LABEL = "extended master secret";
const String PRF_KEY_EXPANSION_LABEL = "key expansion";
const String PRF_VERIFY_DATA_CLIENT_LABEL = "client finished";
const String PRF_VERIFY_DATA_SERVER_LABEL = "server finished";

// PRF with PSK for the pre-master secret
List<int> prfPskPreMasterSecret(List<int> psk) {
  final pskLen = psk.length;

  List<int> out = List<int>.filled(2 + pskLen + 2, 0);
  out.setRange(2, 2 + pskLen, psk);

  final pskLenBytes = ByteData(2)..setUint16(0, pskLen, Endian.big);
  out.setRange(0, 2, pskLenBytes.buffer.asUint8List());
  out.setRange(2 + pskLen, 2 + pskLen + 2, pskLenBytes.buffer.asUint8List());

  return out;
}

// PRF for the pre-master secret based on curve
List<int> prfPreMasterSecret(
  List<int> publicKey,
  List<int> privateKey,
  int curve,
) {
  switch (curve) {
    // case NamedCurve.P256:
    //   return ellipticCurvePreMasterSecret(publicKey, privateKey, curve);
    // case NamedCurve.P384:
    //   return ellipticCurvePreMasterSecret(publicKey, privateKey, curve);
    case 25519:
      return ellipticCurvePreMasterSecret(publicKey, privateKey, curve);
    default:
      throw Exception("Invalid Named Curve");
  }
}

List<int> ellipticCurvePreMasterSecret(
    List<int> publicKey, List<int> privateKey, int curve) {
  // Implement elliptic curve Diffie-Hellman computation here
  // Placeholder logic for elliptic curve pre-master secret generation
  // Perform Diffie-Hellman key exchange using X25519
  return X25519(privateKey, publicKey);
}

// HMAC function for SHA-256
List<int> hmacSha(CipherSuiteHash h, List<int> key, List<int> data) {
  final hmac = Hmac(sha256, key); // Defaulting to SHA-256 for now
  return hmac.convert(data).bytes;
}

// P_hash PRF for the key material generation
List<int> prfPHash(
    List<int> secret, List<int> seed, int requestedLength, CipherSuiteHash h) {
  List<int> lastRound = List<int>.from(seed);
  List<int> out = [];
  final iterations = (requestedLength / 32).ceil();

  for (int i = 0; i < iterations; i++) {
    lastRound = hmacSha(h, secret, lastRound);

    List<int> lastRoundSeed = List<int>.from(lastRound)..addAll(seed);
    final withSecret = hmacSha(h, secret, lastRoundSeed);

    out.addAll(withSecret);
  }

  return out.sublist(0, requestedLength);
}

// Generate extended master secret
List<int> prfExtendedMasterSecret(
    List<int> preMasterSecret, List<int> sessionHash, CipherSuiteHash h) {
  List<int> seed = utf8.encode(PRF_EXTENDED_MASTER_SECRET_LABEL) + sessionHash;
  return prfPHash(preMasterSecret, seed, 48, h);
}

// Generate master secret
List<int> prfMasterSecret(List<int> preMasterSecret, List<int> clientRandom,
    List<int> serverRandom, CipherSuiteHash h) {
  List<int> seed =
      utf8.encode(PRF_MASTER_SECRET_LABEL) + clientRandom + serverRandom;
  return prfPHash(preMasterSecret, seed, 48, h);
}

// Generate encryption keys from master secret
EncryptionKeys prfEncryptionKeys(
  List<int> masterSecret,
  List<int> clientRandom,
  List<int> serverRandom,
  int prfMacLen,
  int prfKeyLen,
  int prfIvLen,
  CipherSuiteHash h,
) {
  List<int> seed =
      utf8.encode(PRF_KEY_EXPANSION_LABEL) + serverRandom + clientRandom;
  final material = prfPHash(
    masterSecret,
    seed,
    (2 * prfMacLen) + (2 * prfKeyLen) + (2 * prfIvLen),
    h,
  );

  List<int> keyMaterial = List<int>.from(material);

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

// Generate verification data for client and server
List<int> prfVerifyData(List<int> masterSecret, List<int> handshakeBodies,
    String label, CipherSuiteHash h) {
  final hasher = sha256.convert(handshakeBodies);
  List<int> seed = utf8.encode(label) + hasher.bytes;
  return prfPHash(masterSecret, seed, 12, h);
}

List<int> prfVerifyDataClient(
    List<int> masterSecret, List<int> handshakeBodies, CipherSuiteHash h) {
  return prfVerifyData(
      masterSecret, handshakeBodies, PRF_VERIFY_DATA_CLIENT_LABEL, h);
}

List<int> prfVerifyDataServer(
    List<int> masterSecret, List<int> handshakeBodies, CipherSuiteHash h) {
  return prfVerifyData(
      masterSecret, handshakeBodies, PRF_VERIFY_DATA_SERVER_LABEL, h);
}

// Example of MAC computation using HMAC-SHA1
List<int> prfMac(
  int epoch,
  int sequenceNumber,
  int contentType,
  int protocolVersionMajor,
  int protocolVersionMinor,
  List<int> payload,
  List<int> key,
) {
  final hmac = Hmac(sha1, key);
  final msg = [
    ...(ByteData(2)..setUint16(0, epoch, Endian.big)).buffer.asUint8List(),
    ...(ByteData(6)..setUint64(0, sequenceNumber)).buffer.asUint8List(),
    contentType,
    protocolVersionMajor,
    protocolVersionMinor,
    ...(ByteData(2)..setUint16(0, payload.length, Endian.big))
        .buffer
        .asUint8List(),
    ...payload,
  ];

  return hmac.convert(msg).bytes;
}

void main() {
  // Example usage of the functions
  List<int> preMasterSecret = utf8.encode("pre master secret");
  List<int> clientRandom = utf8.encode("client random");
  List<int> serverRandom = utf8.encode("server random");

  List<int> masterSecret = prfMasterSecret(
      preMasterSecret, clientRandom, serverRandom, CipherSuiteHash.sha256);
  print(masterSecret);
}
