import 'dart:typed_data';

import '../handshake/server_key_exchange.dart';

const int EXTENSION_SUPPORTED_GROUPS_HEADER_SIZE = 6;

// enum NamedCurve {
//   // Add named curve values here (e.g., P-256, P-384, etc.)
//   // Example:
//   P256 = 0x0017,
//   P384 = 0x0018,
//   Unsupported,
// }

enum ExtensionValue {
  supportedEllipticCurves,
}

class ExtensionSupportedEllipticCurves {
  List<NamedCurve> ellipticCurves;

  ExtensionSupportedEllipticCurves({required this.ellipticCurves});

  // Returns the extension value
  int extensionValue() {
    return ExtensionValue.supportedEllipticCurves.index;
  }

  // Returns the size of the ExtensionSupportedEllipticCurves structure
  int size() {
    return 2 + 2 + ellipticCurves.length * 2;
  }

  // Serialize the object to bytes
  void marshal(ByteData writer) {
    writer.setUint16(0, 2 + 2 * ellipticCurves.length, Endian.big);
    writer.setUint16(2, 2 * ellipticCurves.length, Endian.big);

    int offset = 4;
    for (var curve in ellipticCurves) {
      writer.setUint16(offset, curve.index, Endian.big);
      offset += 2;
    }
  }

  // Deserialize from bytes
  ExtensionSupportedEllipticCurves unmarshal(Uint8List bytes) {
    if (bytes.length < EXTENSION_SUPPORTED_GROUPS_HEADER_SIZE) {
      throw FormatException("Invalid ExtensionSupportedEllipticCurves data");
    }

    int groupCount = (bytes[2] << 8 | bytes[3]) ~/ 2;
    List<NamedCurve> ellipticCurves = [];

    int offset = 4;
    for (int i = 0; i < groupCount; i++) {
      int curveValue = (bytes[offset] << 8 | bytes[offset + 1]);
      NamedCurve curve = NamedCurve.values.firstWhere(
        (e) => e.index == curveValue,
        orElse: () => NamedCurve.Unsupported,
      );
      ellipticCurves.add(curve);
      offset += 2;
    }

    return ExtensionSupportedEllipticCurves(ellipticCurves: ellipticCurves);
  }

  dynamic decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    var curvesLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0);

    offset += 2;
    var curvesCount = curvesLength / 2;
    // e.Curves = make([]Curve, curvesCount)
    for (int i = 0; i < curvesCount; i++) {
      ellipticCurves.add(NamedCurve.fromInt(
          ByteData.sublistView(buf, offset, offset + 2).getUint16(0)));
      offset += 2;
    }

    return null;
  }

  @override
  String toString() {
    return 'ExtensionSupportedEllipticCurves(ellipticCurves: $ellipticCurves)';
  }
}

void main() {
  // Example usage

  // Create a list of elliptic curves
  final ellipticCurves = [NamedCurve.X25519];

  final extension =
      ExtensionSupportedEllipticCurves(ellipticCurves: ellipticCurves);
  print('ExtensionSupportedEllipticCurves: $extension');

  // Serialize to bytes
  final buffer = ByteData(extension.size());
  extension.marshal(buffer);

  // Deserialize from bytes
  final serializedBytes = buffer.buffer.asUint8List();
  // final deserialized =
  //     ExtensionSupportedEllipticCurves.unmarshal(serializedBytes);
  // print('Deserialized ExtensionSupportedEllipticCurves: $deserialized');
}
