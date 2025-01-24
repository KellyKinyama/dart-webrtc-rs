import 'dart:convert';
import 'dart:typed_data';

const int EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME = 0;

class ExtensionServerName {
  final String serverName;

  ExtensionServerName(this.serverName);

  // Returns the extension type value (ServerName)
  int extensionValue() {
    return ExtensionValue.serverName.index;
  }

  // Calculates the size of the extension
  int size() {
    return 2 + 2 + 1 + 2 + serverName.length;
  }

  // Marshals the ExtensionServerName into bytes
  void marshal(ByteData writer) {
    writer.setUint16(0, 2 + 1 + 2 + serverName.length, Endian.big);
    writer.setUint16(2, 1 + 2 + serverName.length, Endian.big);
    writer.setUint8(4, EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME);
    writer.setUint16(5, serverName.length, Endian.big);
    writer.buffer
        .asUint8List()
        .setRange(7, 7 + serverName.length, utf8.encode(serverName));
  }

  // Unmarshals bytes into an ExtensionServerName object
  static ExtensionServerName unmarshal(Uint8List bytes) {
    int offset = 0;

    final length1 = (bytes[offset] << 8 | bytes[offset + 1]);
    offset += 2;

    final length2 = (bytes[offset] << 8 | bytes[offset + 1]);
    offset += 2;

    final nameType = bytes[offset++];
    if (nameType != EXTENSION_SERVER_NAME_TYPE_DNSHOST_NAME) {
      throw FormatException("Invalid SNI format");
    }

    final bufLen = (bytes[offset] << 8 | bytes[offset + 1]);
    offset += 2;

    final buf = bytes.sublist(offset, offset + bufLen);
    final serverName = utf8.decode(buf);

    return ExtensionServerName(serverName);
  }

  @override
  String toString() {
    // TODO: implement toString
    return "{Extension: severname: $serverName}";
  }
}

enum ExtensionValue {
  serverName,
  supportedEllipticCurves,
  supportedPointFormats,
  supportedSignatureAlgorithms,
  useSrtp,
  useExtendedMasterSecret,
  renegotiationInfo,
  unsupported,
}

void main() {
  // Example usage
  final serverName = ExtensionServerName('example.com');
  final size = serverName.size();
  //print('Extension size: $size');

  // Marshal into bytes
  final writer = ByteData(100);
  serverName.marshal(writer);
  //print('Marshalled data: ${writer.buffer.asUint8List()}');

  // Unmarshal from bytes
  final unmarshalled =
      ExtensionServerName.unmarshal(writer.buffer.asUint8List());
  //print('Unmarshalled server name: ${unmarshalled.serverName}');
}
