import 'dart:typed_data';

const int EXTENSION_USE_EXTENDED_MASTER_SECRET_HEADER_SIZE = 4;

enum ExtensionValue {
  useExtendedMasterSecret,
}

class ExtensionUseExtendedMasterSecret {
  bool supported;

  ExtensionUseExtendedMasterSecret({required this.supported});

  // Returns the extension value
  int extensionValue() {
    return ExtensionValue.useExtendedMasterSecret.index;
  }

  // Returns the size of the ExtensionUseExtendedMasterSecret structure
  int size() {
    return 2;
  }

  // Serialize the object to bytes
  void marshal(ByteData writer) {
    // length
    writer.setUint16(0, 0, Endian.big); // Write length (0 in this case)
  }

  // Deserialize from bytes
  static ExtensionUseExtendedMasterSecret unmarshal(Uint8List bytes) {
    if (bytes.length < 2) {
      throw FormatException("Invalid ExtensionUseExtendedMasterSecret data");
    }

    return ExtensionUseExtendedMasterSecret(supported: true);
  }

  dynamic decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    return null;
  }

  Uint8List encode() {
    return Uint8List(0); // No data to encode for this extension
  }

  @override
  String toString() {
    return 'ExtensionUseExtendedMasterSecret(supported: $supported)';
  }
}

void main() {
  // Example usage

  // Create an example ExtensionUseExtendedMasterSecret
  final extensionUseExtendedMasterSecret =
      ExtensionUseExtendedMasterSecret(supported: true);
  //print('ExtensionUseExtendedMasterSecret: $extensionUseExtendedMasterSecret');

  // Serialize to bytes
  final buffer = ByteData(extensionUseExtendedMasterSecret.size());
  extensionUseExtendedMasterSecret.marshal(buffer);

  // Deserialize from bytes
  final serializedBytes = buffer.buffer.asUint8List();
  final deserialized =
      ExtensionUseExtendedMasterSecret.unmarshal(serializedBytes);
  //print('Deserialized ExtensionUseExtendedMasterSecret: $deserialized');
}
