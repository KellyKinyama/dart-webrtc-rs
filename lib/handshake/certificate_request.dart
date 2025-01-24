import 'dart:typed_data';

import '../record_layer_header.dart';
import 'handshake_header.dart';
import 'server_key_exchange.dart';

class HandshakeMessageCertificateRequest {
  final List<ClientCertificateType> certificateTypes;
  final List<SignatureHashAlgorithm> signatureHashAlgorithms;

  HandshakeMessageCertificateRequest({
    required this.certificateTypes,
    required this.signatureHashAlgorithms,
  });

  // Handshake type

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  // Handshake type
  HandshakeType getHandshakeType() {
    return HandshakeType.CertificateRequest;
  }

  // Calculate size
  int size() {
    return 1 +
        certificateTypes.length +
        2 +
        signatureHashAlgorithms.length * 2 +
        2; // Distinguished Names Length
  }

  // Marshal to byte array
  Uint8List marshal() {
    final byteData = BytesBuilder();

    // Write certificate types
    byteData.addByte(certificateTypes.length);
    for (var type in certificateTypes) {
      byteData.addByte(type.value);
    }

    // Write signature hash algorithms
    byteData.addByte((signatureHashAlgorithms.length * 2) >> 8);
    byteData.addByte((signatureHashAlgorithms.length * 2) & 0xFF);
    for (var algo in signatureHashAlgorithms) {
      byteData.addByte(algo.hash.value);
      byteData.addByte(algo.signature.value);
    }

    // Write Distinguished Names Length (always 0x0000)
    byteData.add([0x00, 0x00]);

    return byteData.toBytes();
  }

  // Unmarshal from byte array
  static HandshakeMessageCertificateRequest unmarshal(Uint8List data) {
    final reader = ByteData.sublistView(data);
    int offset = 0;

    // Read certificate types
    final certificateTypesLength = reader.getUint8(offset++);
    final certificateTypes = <ClientCertificateType>[];
    for (int i = 0; i < certificateTypesLength; i++) {
      final certType = ClientCertificateType.fromInt(reader.getUint8(offset++));
      certificateTypes.add(certType);
    }

    // Read signature hash algorithms
    final signatureHashAlgorithmsLength = reader.getUint16(offset);
    offset += 2;

    final signatureHashAlgorithms = <SignatureHashAlgorithm>[];
    for (int i = 0; i < signatureHashAlgorithmsLength; i += 2) {
      final hash = HashAlgorithm.fromInt(reader.getUint8(offset++));
      final signature = SignatureAlgorithm.values[reader.getUint8(offset++)];
      signatureHashAlgorithms
          .add(SignatureHashAlgorithm(hash: hash, signature: signature));
    }

    // Skip Distinguished Names Length (always 0x0000)
    offset += 2;

    return HandshakeMessageCertificateRequest(
      certificateTypes: certificateTypes,
      signatureHashAlgorithms: signatureHashAlgorithms,
    );
  }

  @override
  String toString() {
    return 'HandshakeMessageCertificateRequest(certificateTypes: $certificateTypes, signatureHashAlgorithms: $signatureHashAlgorithms)';
  }

  static decode(Uint8List buf, int offset, int arrayLen) {}
}

enum ClientCertificateType {
  RsaSign(1),
  EcdsaSign(64),
  Unsupported(255);

  const ClientCertificateType(this.value);
  final int value;

  factory ClientCertificateType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

// enum HashAlgorithm { sha256, sha384, sha512, unsupported }

enum SignatureAlgorithm {
  Rsa(1),
  Ecdsa(3),
  Ed25519(7),
  unsupported(255);

  const SignatureAlgorithm(this.value);
  final int value;

  factory SignatureAlgorithm.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class SignatureHashAlgorithm {
  final HashAlgorithm hash;
  final SignatureAlgorithm signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});

  @override
  String toString() {
    return 'SignatureHashAlgorithm(hash: $hash, signature: $signature)';
  }
}

void main() {
  // Example usage
  final request = HandshakeMessageCertificateRequest(
    certificateTypes: [
      ClientCertificateType.RsaSign,
      ClientCertificateType.EcdsaSign
    ],
    signatureHashAlgorithms: [
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha256, signature: SignatureAlgorithm.Ecdsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.Sha384, signature: SignatureAlgorithm.Rsa),
    ],
  );

  // Marshal the object to bytes
  final marshalledData = request.marshal();
  //print('Marshalled Data: $marshalledData');

  // Unmarshal back to an object
  final unmarshalledData =
      HandshakeMessageCertificateRequest.unmarshal(raw_certificate_request);
  //print('Unmarshalled Data: $unmarshalledData');
}

final raw_certificate_request = Uint8List.fromList([
  0x02,
  0x01,
  0x40,
  0x00,
  0x0C,
  0x04,
  0x03,
  0x04,
  0x01,
  0x05,
  0x03,
  0x05,
  0x01,
  0x06,
  0x01,
  0x02,
  0x01,
  0x00,
  0x00,
]);
