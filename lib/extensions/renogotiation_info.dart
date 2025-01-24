import 'dart:typed_data';

const int RENEGOTIATION_INFO_HEADER_SIZE = 5;

enum ExtensionValue {
  renegotiationInfo,
}

class ExtensionRenegotiationInfo {
  int renegotiatedConnection;

  ExtensionRenegotiationInfo(int i, {required this.renegotiatedConnection});

  // Returns the extension value
  int extensionValue() {
    return ExtensionValue.renegotiationInfo.index;
  }

  // Returns the size of the ExtensionRenegotiationInfo structure
  int size() {
    return 3;
  }

  // Serialize the object to bytes
  void marshal(ByteData writer) {
    writer.setUint16(0, 1, Endian.big); // length
    writer.setUint8(2, renegotiatedConnection);
  }

  // Deserialize from bytes
  static ExtensionRenegotiationInfo unmarshal(Uint8List bytes) {
    if (bytes.length < RENEGOTIATION_INFO_HEADER_SIZE) {
      throw FormatException("Invalid ExtensionRenegotiationInfo data");
    }

    int length = (bytes[0] << 8 | bytes[1]);
    if (length != 1) {
      throw FormatException("Invalid packet length");
    }

    int renegotiatedConnection = bytes[2];

    return ExtensionRenegotiationInfo(0,
        renegotiatedConnection: renegotiatedConnection);
  }

  @override
  String toString() {
    return 'ExtensionRenegotiationInfo(renegotiatedConnection: $renegotiatedConnection)';
  }
}

void main() {
  // Example usage
  final extension = ExtensionRenegotiationInfo(0, renegotiatedConnection: 1);
  //print('ExtensionRenegotiationInfo: $extension');

  // Serialize to bytes
  final buffer = ByteData(extension.size());
  extension.marshal(buffer);

  // Deserialize from bytes
  final serializedBytes = buffer.buffer.asUint8List();
  final deserialized = ExtensionRenegotiationInfo.unmarshal(serializedBytes);
  //print('Deserialized ExtensionRenegotiationInfo: $deserialized');
}
