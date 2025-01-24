import 'dart:convert';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';

import 'package:webrtc_rs/aplication_data.dart';
import '../record_layer_header.dart';
import 'handshake_header.dart';

class HandshakeMessageCertificate {
  static const int handshakeMessageCertificateLengthFieldSize = 3;
  final List<Uint8List> certificate;

  HandshakeMessageCertificate({required this.certificate});

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  // Handshake type
  HandshakeType getHandshakeType() {
    return HandshakeType.Certificate;
  }

  // Calculate size
  int size() {
    int len = 3; // Initial payload size
    for (var r in certificate) {
      len += handshakeMessageCertificateLengthFieldSize + r.length;
    }
    return len;
  }

  // Marshal to byte array
  Uint8List marshal() {
    final byteData = BytesBuilder();

    // Calculate total payload size
    int payloadSize = 0;
    for (var r in certificate) {
      payloadSize += handshakeMessageCertificateLengthFieldSize + r.length;
    }

    // Write total payload size
    _writeUint24(byteData, payloadSize);

    // Write each certificate
    for (var r in certificate) {
      // Write certificate length
      _writeUint24(byteData, r.length);

      // Write certificate body
      byteData.add(r);
    }

    return byteData.toBytes();
  }

  // Unmarshal from byte array
  static HandshakeMessageCertificate unmarshal(Uint8List data) {
    final reader = ByteData.sublistView(data);
    int offset = 0;

    // Read total payload size
    final payloadSize = _readUint24(reader, offset);
    offset += handshakeMessageCertificateLengthFieldSize;

    final List<Uint8List> certificates = [];
    int currentOffset = 0;

    while (currentOffset < payloadSize) {
      // Read certificate length
      final certificateLen = _readUint24(reader, offset);
      offset += handshakeMessageCertificateLengthFieldSize;

      // Read certificate body
      final certificate =
          Uint8List.sublistView(data, offset, offset + certificateLen);
      certificates.add(certificate);

      offset += certificateLen;
      currentOffset +=
          handshakeMessageCertificateLengthFieldSize + certificateLen;
    }

    return HandshakeMessageCertificate(certificate: certificates);
  }

  // Helper to write a 3-byte integer (u24)
  static void _writeUint24(BytesBuilder builder, int value) {
    builder.add([
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ]);
  }

  // Helper to read a 3-byte integer (u24)
  static int _readUint24(ByteData reader, int offset) {
    return (reader.getUint8(offset) << 16) |
        (reader.getUint8(offset + 1) << 8) |
        reader.getUint8(offset + 2);
  }

  @override
  String toString() {
    return 'HandshakeMessageCertificate(certificates: ${certificate.length} items)';
  }

  // Method to load PEM certificate and convert it to Uint8List
  static Uint8List loadPemCertificate(String pem) {
    // Remove the "BEGIN" and "END" lines, and any spaces/newlines
    var cleanPem = pem
        .replaceAll(RegExp(r'-----BEGIN CERTIFICATE-----'), '')
        .replaceAll(RegExp(r'-----END CERTIFICATE-----'), '')
        .replaceAll(RegExp(r'\s+'), '');

    // Decode the base64 string to bytes
    return Base64Decoder().convert(cleanPem);
  }

  // Example of generating a self-signed certificate and using it
  static HandshakeMessageCertificate createSelfSignedCertificate() {
    String pemCertificate =
        generateSelfSignedCertificate(); // PEM string from the function you created earlier
    var rawCertificate = loadPemCertificate(pemCertificate);

    // Create a certificate message with the raw certificate in a list
    return HandshakeMessageCertificate(certificate: [rawCertificate]);
  }

  static String generateSelfSignedCertificate() {
    var pair = CryptoUtils.generateEcKeyPair();
    var privKey = pair.privateKey as ECPrivateKey;
    var pubKey = pair.publicKey as ECPublicKey;
    var dn = {
      'CN': 'Self-Signed',
    };
    var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

    var x509PEM = X509Utils.generateSelfSignedCertificate(
      privKey,
      csr,
      365,
    );
    return x509PEM;
  }
}

void main() {
  // Generate the self-signed certificate and create a handshake message
  var handshakeMessage =
      HandshakeMessageCertificate.createSelfSignedCertificate();

  print("handshakeMessage: $handshakeMessage");

  // Print the size and marshal the handshake message
  print('Handshake size: ${handshakeMessage.size()}');
  print('Handshake message: ${handshakeMessage.marshal()}');
}
