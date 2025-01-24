import 'dart:typed_data';
import 'dart:io';

enum CompressionMethodId {
  Null(0),
  unsupported(255);

  final int value;

  const CompressionMethodId(this.value);

  /// Convert a byte value to a CompressionMethodId
  factory CompressionMethodId.from(int val) {
    switch (val) {
      case 0:
        return CompressionMethodId.Null;
      default:
        return CompressionMethodId.unsupported;
    }
  }
}

class CompressionMethods {
  List<CompressionMethodId> ids;

  /// Constructor
  CompressionMethods({required this.ids});

  /// Get the size of the structure
  int size() {
    return 1 + ids.length;
  }

  /// Marshal the object into bytes
  Uint8List marshal() {
    final bb = BytesBuilder();
    bb.add([ids.length]); // Write the number of compression methods
    for (var id in ids) {
      bb.add([id.value]);
    }
    return bb.toBytes();
  }

  /// Unmarshal the object from bytes
  factory CompressionMethods.unmarshal(
      Uint8List bytes, int offset, int arrayLen) {
    if (bytes.isEmpty) {
      throw FormatException("Invalid CompressionMethods data");
    }

    final compressionMethodsCount = bytes[offset];
    offset++;
    final ids = <CompressionMethodId>[];

    //print("Compression methods count: $compressionMethodsCount");

    for (int i = 0; i < compressionMethodsCount; i++) {
      //print("Compression method: ${bytes[offset]}");
      final id = CompressionMethodId.from(bytes[offset]);
      if (id != CompressionMethodId.unsupported) {
        ids.add(id);
      }
      offset++;
    }

    return CompressionMethods(ids: ids);
  }

  Uint8List decodeCompressionMethodIDs(
      Uint8List buf, int offset, int arrayLen) {
    final count = buf[offset];
    offset++;
    return Uint8List.fromList(buf.sublist(offset, offset + count));
  }

  /// Default compression methods
  static CompressionMethods defaultCompressionMethods() {
    return CompressionMethods(ids: [CompressionMethodId.Null]);
  }

  @override
  String toString() {
    return 'CompressionMethods(ids: $ids)';
  }
}

void main() {
  // Example usage

  // Create default compression methods
  final defaultMethods = CompressionMethods.defaultCompressionMethods();
  //print('Default CompressionMethods: $defaultMethods');

  // Serialize to bytes
  final serialized = defaultMethods.marshal();
  //print('Serialized bytes: $serialized');

  // Deserialize from bytes
  // final deserialized = CompressionMethods.unmarshal(serialized);
  // print('Deserialized CompressionMethods: $deserialized');
}
