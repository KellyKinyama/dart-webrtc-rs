import 'dart:typed_data';

const int EXTENSION_SUPPORTED_POINT_FORMATS_SIZE = 5;

typedef EllipticCurvePointFormat = int;

const int ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED = 0;

enum ExtensionValue {
  supportedPointFormats,
}

class ExtensionSupportedPointFormats {
  List<EllipticCurvePointFormat> pointFormats;

  ExtensionSupportedPointFormats({required this.pointFormats});

  // Returns the extension value
  int extensionValue() {
    return ExtensionValue.supportedPointFormats.index;
  }

  // Returns the size of the ExtensionSupportedPointFormats structure
  int size() {
    return 2 + 1 + pointFormats.length;
  }

  // Serialize the object to bytes
  void marshal(ByteData writer) {
    writer.setUint16(0, 1 + pointFormats.length, Endian.big);
    writer.setUint8(2, pointFormats.length);

    int offset = 3;
    for (var v in pointFormats) {
      writer.setUint8(offset, v);
      offset += 1;
    }
  }

  // Deserialize from bytes
  static ExtensionSupportedPointFormats unmarshal(Uint8List bytes) {
    if (bytes.length < EXTENSION_SUPPORTED_POINT_FORMATS_SIZE) {
      throw FormatException("Invalid ExtensionSupportedPointFormats data");
    }

    int pointFormatCount = bytes[2];
    List<EllipticCurvePointFormat> pointFormats = [];

    int offset = 3;
    for (int i = 0; i < pointFormatCount; i++) {
      pointFormats.add(bytes[offset]);
      offset += 1;
    }

    return ExtensionSupportedPointFormats(pointFormats: pointFormats);
  }

  dynamic decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    var pointFormatsCount = buf[offset];
    offset++;
    //e.PointFormats = make([]PointFormat, pointFormatsCount)
    for (int i = 0; i < pointFormatsCount; i++) {
      pointFormats.add((buf[offset]));
      offset++;
    }

    return null;
  }

  @override
  String toString() {
    return 'ExtensionSupportedPointFormats(pointFormats: $pointFormats)';
  }
}

void main() {
  // Example usage

  // Create a list of point formats
  final pointFormats = [ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED];

  final extension = ExtensionSupportedPointFormats(pointFormats: pointFormats);
  //print('ExtensionSupportedPointFormats: $extension');

  // Serialize to bytes
  final buffer = ByteData(extension.size());
  extension.marshal(buffer);

  // Deserialize from bytes
  final serializedBytes = buffer.buffer.asUint8List();
  final deserialized =
      ExtensionSupportedPointFormats.unmarshal(serializedBytes);
  //print('Deserialized ExtensionSupportedPointFormats: $deserialized');
}
