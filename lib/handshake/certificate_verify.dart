import 'dart:typed_data';
import 'dart:io';

import 'certificate_request.dart';
import 'handshake_header.dart';
import 'server_key_exchange.dart';

class HandshakeMessageCertificateVerify {
  final SignatureHashAlgorithm algorithm;
  final Uint8List signature;

  HandshakeMessageCertificateVerify({
    required this.algorithm,
    required this.signature,
  });

  // Handshake type
  HandshakeType handshakeType() {
    return HandshakeType.CertificateVerify;
  }

  // Calculate size
  int size() {
    return 1 + 1 + 2 + signature.length;
  }

  // Marshal to byte array
  Uint8List marshal() {
    final byteData = BytesBuilder();

    // Write algorithm
    byteData.addByte(algorithm.hash.value);
    byteData.addByte(algorithm.signature.value);

    // Write signature length
    byteData.addByte(signature.length >> 8);
    byteData.addByte(signature.length & 0xFF);

    // Write signature
    byteData.add(signature);

    return byteData.toBytes();
  }

  // Unmarshal from byte array
  static HandshakeMessageCertificateVerify unmarshal(Uint8List data) {
    final reader = ByteData.sublistView(data);
    int offset = 0;

    // Read algorithm
    final hashAlgorithm = HashAlgorithm.fromInt(reader.getUint8(offset++));
    final signatureAlgorithm =
        SignatureAlgorithm.values[reader.getUint8(offset++)];
    final algorithm = SignatureHashAlgorithm(
        hash: hashAlgorithm, signature: signatureAlgorithm);

    // Read signature length
    final signatureLength = reader.getUint16(offset);
    offset += 2;

    // Read signature
    final signature =
        Uint8List.fromList(data.sublist(offset, offset + signatureLength));

    return HandshakeMessageCertificateVerify(
      algorithm: algorithm,
      signature: signature,
    );
  }

  @override
  String toString() {
    return 'HandshakeMessageCertificateVerify(algorithm: $algorithm, signature: ${signature.length} bytes)';
  }

  static decode(Uint8List buf, int offset, int arrayLen) {}
}

void main() {
  // Example usage
  final verifyMessage = HandshakeMessageCertificateVerify(
    algorithm: SignatureHashAlgorithm(
        hash: HashAlgorithm.sha256, signature: SignatureAlgorithm.Ecdsa),
    signature: Uint8List.fromList([0x01, 0x02, 0x03, 0x04]),
  );

  // Marshal the object to bytes
  final marshalledData = verifyMessage.marshal();
  //print('Marshalled Data: $marshalledData');

  // Unmarshal back to an object
  final unmarshalledData =
      HandshakeMessageCertificateVerify.unmarshal(marshalledData);
  //print('Unmarshalled Data: $unmarshalledData');
}
