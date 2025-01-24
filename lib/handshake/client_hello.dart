import 'dart:typed_data';

import '../compression_methods.dart';
import '../extensions/extensions.dart';
import '../extensions/supported_elliptic_curves.dart';
import '../extensions/supported_point_formats.dart';
import '../extensions/use_extended_master_secret.dart';
import '../extensions/use_srtp.dart';
import '../record_layer_header.dart';
import 'handshake_random.dart';
import 'server_key_exchange.dart';

// Stubs and required classes for unmarshalling

enum CipherSuiteId {
  // AES-128-CCM
  Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm(0xc0ac),
  Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8(0xc0ae),

  // AES-128-GCM-SHA256
  Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256(0xc02b),
  Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256(0xc02f),

  // AES-256-CBC-SHA
  Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha(0xc00a),
  Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha(0xc014),

  Tls_Psk_With_Aes_128_Ccm(0xc0a4),
  Tls_Psk_With_Aes_128_Ccm_8(0xc0a8),
  Tls_Psk_With_Aes_128_Gcm_Sha256(0x00a8),

  Unsupported(255);

  const CipherSuiteId(this.value);
  final int value;

  factory CipherSuiteId.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

// class ExtensionSupportedEllipticCurves {
//   final List<NamedCurve> ellipticCurves;

//   ExtensionSupportedEllipticCurves({required this.ellipticCurves});

//   @override
//   String toString() =>
//       'ExtensionSupportedEllipticCurves(ellipticCurves: $ellipticCurves)';

//   dynamic unmarshal(
//       int extensionLength, Uint8List buf, int offset, int arrayLen)
//   //error
//   {
//     var curvesLength =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0);
//     offset += 2;
//     var curvesCount = curvesLength / 2;
//     // e.Curves = make([]Curve, curvesCount)
//     for (int i = 0; i < curvesCount; i++) {
//       ellipticCurves.add(NamedCurve.fromInt(
//           ByteData.sublistView(buf, offset, offset + 2).getUint16(0)));
//       offset += 2;
//     }

//     return null;
//   }
// }

class HandshakeMessageClientHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final Uint8List sessionId;
  final Uint8List cookie;
  final List<CipherSuiteId> cipherSuites;
  final CompressionMethods compressionMethods;
  final Map<ExtensionType, dynamic> extensions;

  HandshakeMessageClientHello({
    required this.version,
    required this.random,
    required this.sessionId,
    required this.cookie,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
  });

  static (HandshakeMessageClientHello, int, bool?) unmarshal(
      Uint8List data, int offset, int arrayLen) {
    final reader = ByteData.sublistView(data);
    // int offset = 0;

    // Read protocol version
    final major = reader.getUint8(offset++);
    final minor = reader.getUint8(offset++);
    final version = ProtocolVersion(major: major, minor: minor);
    //print("version: $version");

    // Read random
    final random = HandshakeRandom.unmarshal(
        data.sublist(offset, offset + HandshakeRandom.size()));
    offset += HandshakeRandom.size();

    //print("Random: $random");

// SessionID
    final sessionIdLength = data[offset];
    offset++;
    final sessionId =
        Uint8List.fromList(data.sublist(offset, offset + sessionIdLength));
    offset += sessionIdLength;
    // Skip SessionID

    // Read cookie
    final cookieLength = reader.getUint8(offset++);
    final cookie = Uint8List.sublistView(data, offset, offset + cookieLength);
    //print("Cookie: $cookie");
    offset += cookieLength;

    // Read cipher suites
    final cipherSuitesLength = reader.getUint16(offset) ~/ 2;
    offset += 2;
    final cipherSuites = <CipherSuiteId>[];
    for (var i = 0; i < cipherSuitesLength; i++) {
      final id = CipherSuiteId.fromInt(reader.getUint16(offset));
      cipherSuites.add(id);
      offset += 2;
    }
    //print("cipher suites: $cipherSuites");

    // var (cmpMethods, decodedOffset) =
    //     decodeCompressionMethodIDs(data, offset, data.length);

    //print("compression methods: $cmpMethods");

    // Read compression methods
    final compressionMethods =
        CompressionMethods.unmarshal(data, offset, data.length);
    offset += compressionMethods.size();

    var (extentionTypes, decodedOffset, error) =
        decodeExtensionMap(data, offset, data.length);
    //print("Extensions: $extentionTypes");
    offset = offset + decodedOffset;

    // // Read extensions
    // final extensionsLength = reader.getUint16(offset);
    // offset += 2;

    // final extensionsData =
    //     Uint8List.sublistView(data, offset, offset + extensionsLength);
    // offset += extensionsLength;

    // final extensions = <Extension>[];
    // int extOffset = 0;
    // while (extOffset < extensionsData.length) {
    //   final extension = Extension.unmarshal(Uint8List.sublistView(
    //       extensionsData, extOffset, extensionsData.length));
    //   extensions.add(extension);
    //   extOffset += extension.size();
    // }

    return (
      HandshakeMessageClientHello(
        version: version,
        random: random,
        sessionId: sessionId,
        cookie: cookie,
        cipherSuites: cipherSuites,
        compressionMethods: compressionMethods,
        extensions: extentionTypes!,
      ),
      offset,
      null
    );
  }

  @override
  String toString() {
    return 'HandshakeMessageClientHello(version: $version, random: $random, cookie: $cookie, cipherSuites: $cipherSuites, compressionMethods: $compressionMethods, extensions: $extensions)';
  }

  // static (dynamic, int, bool?) decode(Uint8List buf, int offset, int arrayLen) {
  //   var (handshake, decodeOffset, err) =
  //       HandshakeMessageClientHello.unmarshal(buf);
  //   return (handshake, decodeOffset, err);
  // }
}

// (List<CipherSuiteId>, int, bool?) decodeCipherSuiteIDs(
//       Uint8List buf, int offset, int arrayLen) {
//     // final length =
//     //     ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     // final count = length ~/ 2;
//     // offset += 2;
//     // return (
//     //   List<intCipherSuiteID>.generate(count, (i) {
//     //     final id = ByteData.sublistView(buf, offset, offset + 2)
//     //         .getUint16(0, Endian.big);
//     //     offset += 2;
//     //     return id;
//     //   }),
//     //   offset,
//     //   null
//     // );

//     var length = uint16(buf.sublist(offset, offset + 2));

//     var count = length ~/ 2;
//     offset += 2;

//     // print("cipher suites length: $count");
//     List<intCipherSuiteID> result = [];
//     for (int i = 0; i < count; i++) {
//       try {
//         result.add(uint16(buf.sublist(offset, offset + 2)));
//         // print("Cipher suit id: ${result[i]}");
//         offset += 2;
//       } catch (e) {
//         return (result, offset, true);
//       }
//     }
//     return (result, offset, null);
//   }

(Uint8List, int) decodeCompressionMethodIDs(
    Uint8List buf, int offset, int arrayLen) {
  final count = buf[offset];
  offset++;
  return (Uint8List.fromList(buf.sublist(offset, offset + count)), offset);
}

(Map<ExtensionType, dynamic>?, int, bool?) decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen)
//(map[ExtensionType]Extension, int, error)
{
  Map<ExtensionType, dynamic> result = {};

  var length = ByteData.sublistView(buf, offset, offset + 2).getUint16(0);
  offset += 2;
  var offsetBackup = offset;
  while (offset < offsetBackup + length) {
    var extensionType = ExtensionType.fromInt(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0));
    offset += 2;
    var extensionLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0);
    offset += 2;
    var extension;
    switch (extensionType) {
      case ExtensionType.UseExtendedMasterSecret:
        extension = ExtensionUseExtendedMasterSecret(supported: true);
      case ExtensionType.UseSRTP:
        extension = ExtensionUseSrtp(protectionProfiles: []);
      case ExtensionType.SupportedPointFormats:
        extension = ExtensionSupportedPointFormats(pointFormats: []);
      case ExtensionType.SupportedEllipticCurves:
        extension = ExtensionSupportedEllipticCurves(ellipticCurves: []);

      //extension.unmarshal(extensionLength, buf, offset, arrayLen);
      default:
      // extension = ExtUnknown(extensionType, extensionLength);
    }
    if (extension != null) {
      var err = extension.decode(extensionLength, buf, offset, arrayLen);

      if (err != null) {
        return (null, offset, err);
      }
      result[extensionType] = extension;
    }
    offset += extensionLength;
  }
  return (result, offset, null);
}

Uint8List encodeExtensionMap(Map<ExtensionType, dynamic> extensions) {
  // Calculate the total length of the encoded extensions
  int totalLength = extensions.entries.fold(0, (sum, entry) {
    int extensionLength = entry.value.size();
    return sum +
        4 +
        extensionLength; // 2 bytes for type, 2 bytes for length, and extension data
  });

  // Create a ByteData buffer to write the encoded extensions
  ByteData writer = ByteData(2 + totalLength);
  int offset = 0;

  // Write the total length of the extensions (2 bytes)
  writer.setUint16(offset, totalLength, Endian.big);
  offset += 2;

  // Iterate over the extensions and write each one
  extensions.forEach((extensionType, extension) {
    // Write ExtensionType (2 bytes)
    writer.setUint16(offset, extensionType.value, Endian.big);
    offset += 2;

    // Write the length of the extension data (2 bytes)
    int extensionLength = extension.size();
    writer.setUint16(offset, extensionLength, Endian.big);
    offset += 2;

    // Write the extension data
    ByteData extensionData = ByteData(extensionLength);
    //extension.marshal(extensionData);
    writer.buffer.asUint8List().setRange(
        offset, offset + extensionLength, extensionData.buffer.asUint8List());
    offset += extensionLength;
  });

  return writer.buffer.asUint8List();
}

void main() {
  // Example raw client hello data
  // final parsedClientHello = HandshakeMessageClientHello(
  //   version: ProtocolVersion(
  //     major: 0xFE,
  //     minor: 0xFD,
  //   ),
  //   random: HandshakeRandom(
  //     gmtUnixTime: (DateTime.now()), // Replace as needed
  //     randomBytes: [
  //       0x42,
  //       0x54,
  //       0xFF,
  //       0x86,
  //       0xE1,
  //       0x24,
  //       0x41,
  //       0x91,
  //       0x42,
  //       0x62,
  //       0x15,
  //       0xAD,
  //       0x16,
  //       0xC9,
  //       0x15,
  //       0x8D,
  //       0x95,
  //       0x71,
  //       0x8A,
  //       0xBB,
  //       0x22,
  //       0xD7,
  //       0x47,
  //       0xEC,
  //       0xD8,
  //       0x3D,
  //       0xDC,
  //       0x4B,
  //     ],
  //   ),
  //   cookie: Uint8List.fromList([
  //     0xE6,
  //     0x14,
  //     0x3A,
  //     0x1B,
  //     0x04,
  //     0xEA,
  //     0x9E,
  //     0x7A,
  //     0x14,
  //     0xD6,
  //     0x6C,
  //     0x57,
  //     0xD0,
  //     0x0E,
  //     0x32,
  //     0x85,
  //     0x76,
  //     0x18,
  //     0xDE,
  //     0xD8,
  //   ]),
  //   cipherSuites: [
  //     CipherSuiteId.Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
  //     CipherSuiteId.Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
  //   ],
  //   compressionMethods: CompressionMethods(
  //     ids: [CompressionMethodId.Null],
  //   ),
  //   extensions: {},
  // );

  // Unmarshal the client hello data
  // final clientHello = HandshakeMessageClientHello.unmarshal(rawClientHello);
  // print('Successfully unmarshalled client hello:');
  // print(clientHello);
}

final rawClientHello = Uint8List.fromList([
  0xfe,
  0xfd,
  0xb6,
  0x2f,
  0xce,
  0x5c,
  0x42,
  0x54,
  0xff,
  0x86,
  0xe1,
  0x24,
  0x41,
  0x91,
  0x42,
  0x62,
  0x15,
  0xad,
  0x16,
  0xc9,
  0x15,
  0x8d,
  0x95,
  0x71,
  0x8a,
  0xbb,
  0x22,
  0xd7,
  0x47,
  0xec,
  0xd8,
  0x3d,
  0xdc,
  0x4b,
  0x00,
  0x14,
  0xe6,
  0x14,
  0x3a,
  0x1b,
  0x04,
  0xea,
  0x9e,
  0x7a,
  0x14,
  0xd6,
  0x6c,
  0x57,
  0xd0,
  0x0e,
  0x32,
  0x85,
  0x76,
  0x18,
  0xde,
  0xd8,
  0x00,
  0x04,
  0xc0,
  0x2b,
  0xc0,
  0x0a,
  0x01,
  0x00,
  0x00,
  0x08,
  0x00,
  0x0a,
  0x00,
  0x04,
  0x00,
  0x02,
  0x00,
  0x1d
]);
