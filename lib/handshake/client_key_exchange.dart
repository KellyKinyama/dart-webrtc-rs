import 'dart:typed_data';
import 'dart:io';

import 'handshake_header.dart';

class HandshakeMessageClientKeyExchange {
  final List<int> identityHint;
  final List<int> publicKey;

  HandshakeMessageClientKeyExchange({
    required this.identityHint,
    required this.publicKey,
  });

  // Handshake type
  HandshakeType handshakeType() {
    return HandshakeType.ClientKeyExchange;
  }

  // Calculate size
  int size() {
    if (publicKey.isNotEmpty) {
      return 1 + publicKey.length;
    } else {
      return 2 + identityHint.length;
    }
  }

  // Marshal to byte array
  Uint8List marshal() {
    final byteData = BytesBuilder();

    if ((identityHint.isNotEmpty && publicKey.isNotEmpty) ||
        (identityHint.isEmpty && publicKey.isEmpty)) {
      throw Error(); // Replace with your own error handling.
    }

    if (publicKey.isNotEmpty) {
      byteData.addByte(publicKey.length);
      byteData.add(Uint8List.fromList(publicKey));
    } else {
      byteData.addByte(identityHint.length);
      byteData.add(Uint8List.fromList(identityHint));
    }

    return byteData.toBytes();
  }

  // Unmarshal from byte array
  static HandshakeMessageClientKeyExchange unmarshal(Uint8List data) {
    int pskLength = ((data[0] << 8) | data[1]);

    if (data.length == pskLength + 2) {
      return HandshakeMessageClientKeyExchange(
        identityHint: data.sublist(2),
        publicKey: [],
      );
    }

    int publicKeyLength = data[0];
    if (data.length != publicKeyLength + 1) {
      throw Error(); // Replace with your own error handling.
    }

    return HandshakeMessageClientKeyExchange(
      identityHint: [],
      publicKey: data.sublist(1),
    );
  }

  @override
  String toString() {
    // TODO: implement toString
    return "{identityHint: $identityHint, publicKey: $publicKey}";
  }

  static decode(Uint8List buf, int offset, int arrayLen) {}
}

void main() async {
  // Example usage
  final handshake = HandshakeMessageClientKeyExchange(
    identityHint: [1, 2, 3],
    publicKey: [],
  );

  // Marshal the data to a byte array
  Uint8List marshalledData = handshake.marshal();
  // await File('handshake_data.dat').writeAsBytes(marshalledData);

  // Read the byte array back from the file and unmarshal it
  // Uint8List unmarshalledData = await File('handshake_data.dat').readAsBytes();
  final unmarshalled =
      HandshakeMessageClientKeyExchange.unmarshal(raw_client_key_exchange);

  //print('Unmarshalled: ${unmarshalled.publicKey}');
  //print('Wanted:       ${raw_client_key_exchange.sublist(1)}');
}

final raw_client_key_exchange = Uint8List.fromList([
  0x20,
  0x26,
  0x78,
  0x4a,
  0x78,
  0x70,
  0xc1,
  0xf9,
  0x71,
  0xea,
  0x50,
  0x4a,
  0xb5,
  0xbb,
  0x00,
  0x76,
  0x02,
  0x05,
  0xda,
  0xf7,
  0xd0,
  0x3f,
  0xe3,
  0xf7,
  0x4e,
  0x8a,
  0x14,
  0x6f,
  0xb7,
  0xe0,
  0xc0,
  0xff,
  0x54,
]);
