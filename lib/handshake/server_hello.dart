import 'dart:convert';
import 'dart:typed_data';

import '../compression_methods.dart';
import '../extensions/extensions.dart';
import '../record_layer_header.dart';
import 'client_hello.dart';
import 'handshake_header.dart';
import 'handshake_random.dart';

class HandshakeMessageServerHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final Uint8List sessionId;
  final CipherSuiteId cipherSuite;
  final CompressionMethodId compressionMethod;
  // final List<Extension> extensions;
  final Map<ExtensionType, dynamic> extensions;

  HandshakeMessageServerHello({
    required this.version,
    required this.random,
    required this.sessionId,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensions,
  });

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHello;
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  // Uint8List marshal() {
  //   // Calculate the total size of the marshaled data
  //   int totalSize = 2 +
  //       HandshakeRandom.size() +
  //       1 +
  //       2 +
  //       1 +
  //       2; // Version + Random + Session ID + CipherSuite + CompressionMethod + Extensions Length

  //   totalSize += extensions.entries.fold<int>(0, (sum, entry) {
  //     return sum +
  //         4 +
  //         (entry.value.size()
  //             as int); // Cast size() result to int // 2 bytes for type, 2 bytes for length, and extension size
  //   });

  //   // Allocate buffer for marshaling
  //   ByteData writer = ByteData(totalSize);
  //   int offset = 0;

  //   // Write ProtocolVersion
  //   writer.setUint8(offset++, version.major);
  //   writer.setUint8(offset++, version.minor);

  //   // Write HandshakeRandom
  //   Uint8List randomBytes = random.marshal();
  //   writer.buffer
  //       .asUint8List()
  //       .setRange(offset, offset + HandshakeRandom.size(), randomBytes);
  //   offset += HandshakeRandom.size();

  //   // Write Session ID (assuming no session ID, length = 0)
  //   writer.setUint8(offset++, 0x00);

  //   // Write CipherSuite
  //   writer.setUint16(offset, cipherSuite.value, Endian.big);
  //   offset += 2;

  //   // Write CompressionMethod
  //   writer.setUint8(offset++, compressionMethod.value);

  //   // Write Extensions
  //   Uint8List extensionsBuffer = encodeExtensionMap(extensions);
  //   // writer.setUint16(offset, extensionsBuffer.length, Endian.big);
  //   // offset += 2;

  //   // writer.buffer
  //   //     .asUint8List()
  //   //     .setRange(offset, offset + extensionsBuffer.length, extensionsBuffer);

  //   return Uint8List.fromList(
  //       writer.buffer.asUint8List().toList() + extensionsBuffer);
  //   // Return the marshaled data as Uint8List
  //   //return writer.buffer.asUint8List();
  // }

  Uint8List marshal() {
    final bb = BytesBuilder();
    // Calculate the total size of the marshaled data

    // Allocate buffer for marshaling

    // Write ProtocolVersion
    bb.add([version.major, version.minor]);

    // Write HandshakeRandom

    bb.add(random.marshal());

    // Write Session ID (assuming no session ID, length = 0)
    bb.addByte(sessionId.length);
    if (sessionId.isNotEmpty) bb.add(sessionId);

    // Write CipherSuite
    ByteData bd = ByteData(2);
    bd.setUint16(0, cipherSuite.value);
    bb.add(bd.buffer.asUint8List());

    // Write CompressionMethod
    bb.addByte(compressionMethod.value);

    // Write Extensions
    bb.add(encodeExtensionMap(extensions));

    // Debug prints to check buffer sizes and offsets
    // print('Total Size: $totalSize');
    // print('Offset before setting extensions: $offset');
    // print('Extensions Buffer Length: ${extensionsBuffer.length}');

    // // Ensure the range is within the buffer size
    // if (offset + extensionsBuffer.length > totalSize) {
    //   throw RangeError('Extensions buffer exceeds allocated buffer size');
    // }

    // writer.buffer
    //     .asUint8List()
    //     .setRange(offset, offset + extensionsBuffer.length, extensionsBuffer);

    return bb.toBytes();
    // Return the marshaled data as Uint8List
    // return writer.buffer.asUint8List();
  }

  static HandshakeMessageServerHello unmarshal(Uint8List data) {
    int offset = 0;

    int major = data[offset++];
    int minor = data[offset++];

    HandshakeRandom random = HandshakeRandom.unmarshal(data.sublist(offset));
    offset += HandshakeRandom.size();

    int sessionIdLength = data[offset++];
    final sessionID = data.sublist(offset, offset + sessionIdLength);
    offset += sessionIdLength;

    int cipherSuiteValue = (data[offset++] << 8) | data[offset++];
    CipherSuiteId cipherSuite = CipherSuiteId.fromInt(cipherSuiteValue);

    int compressionMethodValue = data[offset++];
    CompressionMethodId compressionMethod =
        CompressionMethodId.from(compressionMethodValue);

    var (extentionTypes, decodedOffset, error) =
        decodeExtensionMap(data, offset, data.length);
    //print("Extensions: $extentionTypes");

    // List<Extension> extensions = [];
    // int extensionBufferLen = (data[offset++] << 8) | data[offset++];
    // List<int> extensionBuffer =
    //     data.sublist(offset, offset + extensionBufferLen);
    // offset += extensionBufferLen;

    // while (offset < extensionBufferLen) {
    //   // Assuming Extension::unmarshal works based on the extension format
    //   Extension extension = Extension.unmarshal(
    //       Uint8List.fromList(extensionBuffer.sublist(offset)));
    //   extensions.add(extension);

    //   int extensionLen =
    //       (extensionBuffer[offset + 2] << 8) | extensionBuffer[offset + 3];
    //   offset += 4 + extensionLen;
    // }

    return HandshakeMessageServerHello(
      version: ProtocolVersion(major: major, minor: minor),
      random: random,
      sessionId: sessionID,
      cipherSuite: cipherSuite,
      compressionMethod: compressionMethod,
      extensions: extentionTypes!,
    );
  }

  @override
  String toString() {
    return 'HandshakeMessageServerHello(version: $version, random: $random, cipherSuite: $cipherSuite, compressionMethod: $compressionMethod, extensions: $extensions)';
  }

  static decode(Uint8List buf, int offset, int arrayLen) {}
}

void main() {
  // Example usage of HandshakeMessageServerHello
  // final helloMessage = HandshakeMessageServerHello(
  //   version: ProtocolVersion(major: 254, minor: 253),
  //   random: HandshakeRandom(),
  //   cipherSuite: CipherSuiteId.fromInt(0x1301),
  //   compressionMethod: CompressionMethodId(0),
  //   extensions: [],
  // );

  // final size = helloMessage.size();
  // print('HandshakeMessageServerHello size: $size');

  // final writer = ByteData(100);
  // helloMessage.marshal(writer);
  // print('Marshaled data: ${writer.buffer.asUint8List()}');

  final unmarshalledMessage =
      HandshakeMessageServerHello.unmarshal(raw_server_hello);
  // print('Unmarshalled message: $unmarshalledMessage');
  // print("marshalled: ${unmarshalledMessage.marshal()}");
  // print("Expected:   $raw_server_hello");
}

final raw_server_hello = Uint8List.fromList([
  0xfe,
  0xfd,
  0x21,
  0x63,
  0x32,
  0x21,
  0x81,
  0x0e,
  0x98,
  0x6c,
  0x85,
  0x3d,
  0xa4,
  0x39,
  0xaf,
  0x5f,
  0xd6,
  0x5c,
  0xcc,
  0x20,
  0x7f,
  0x7c,
  0x78,
  0xf1,
  0x5f,
  0x7e,
  0x1c,
  0xb7,
  0xa1,
  0x1e,
  0xcf,
  0x63,
  0x84,
  0x28,
  0x00,
  0xc0,
  0x2b,
  0x00,
  0x00,
  0x00,
]);
