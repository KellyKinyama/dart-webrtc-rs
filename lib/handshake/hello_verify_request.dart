import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';

import '../record_layer_header.dart';
import 'handshake_header.dart';

/// ProtocolVersion represents the server version with major and minor components.
// class ProtocolVersion {
//   final int major;
//   final int minor;

//   ProtocolVersion(this.major, this.minor);

//   @override
//   bool operator ==(Object other) =>
//       identical(this, other) ||
//       other is ProtocolVersion && major == other.major && minor == other.minor;

//   @override
//   int get hashCode => major.hashCode ^ minor.hashCode;

//   @override
//   String toString() => 'ProtocolVersion(major: $major, minor: $minor)';
// }

/// Enum to represent handshake type.

/// Error class to handle exceptions.
class HandshakeError implements Exception {
  final String message;

  HandshakeError(this.message);

  @override
  String toString() => 'HandshakeError: $message';
}

/// Represents the HandshakeMessageHelloVerifyRequest structure.
class HandshakeMessageHelloVerifyRequest {
  final ProtocolVersion version;
  final List<int> cookie;

  HandshakeMessageHelloVerifyRequest({
    required this.version,
    required this.cookie,
  });

  /// Returns the handshake type.
  HandshakeType get handshakeType => HandshakeType.HelloVerifyRequest;

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.HelloVerifyRequest;
  }

  /// Returns the size of the marshaled data.
  int get size => 1 + 1 + 1 + cookie.length;

  /// Serializes the object into a byte buffer.
  Uint8List marshal() {
    if (cookie.length > 255) {
      throw HandshakeError('Cookie length exceeds the maximum allowed size.');
    }

    final buffer = BytesBuilder();
    buffer.addByte(version.major);
    buffer.addByte(version.minor);
    buffer.addByte(cookie.length);
    buffer.add(cookie);

    return buffer.toBytes();
  }

  /// Deserializes a byte buffer into a `HandshakeMessageHelloVerifyRequest` object.
  static (HandshakeMessageHelloVerifyRequest, int, bool?) unmarshal(
      Uint8List data, int offset, int arrayLen) {
    if (data.length < 3) {
      throw HandshakeError('Buffer too small for unmarshalling.');
    }

    final major = data[offset];
    final minor = data[offset + 1];
    final cookieLength = data[offset + 2];

    if (data.length < 3 + cookieLength) {
      throw HandshakeError('Buffer too small for specified cookie length.');
    }

    final cookie = data.sublist(offset + 3, offset + 3 + cookieLength);

    return (
      HandshakeMessageHelloVerifyRequest(
        version: ProtocolVersion(major: major, minor: minor),
        cookie: cookie,
      ),
      0,
      null
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HandshakeMessageHelloVerifyRequest &&
          version == other.version &&
          const ListEquality().equals(cookie, other.cookie);

  @override
  int get hashCode => version.hashCode ^ const ListEquality().hash(cookie);

  @override
  String toString() =>
      'HandshakeMessageHelloVerifyRequest(version: $version, cookie: $cookie)';
}

void main() {
  // Example usage:

  // final version = ProtocolVersion(3, 3); // Example version (e.g., TLS 1.2)
  // final cookie = Uint8List.fromList([1, 2, 3, 4, 5]);

  // // Create a handshake message.
  // final message = HandshakeMessageHelloVerifyRequest(
  //   version: version,
  //   cookie: cookie,
  // );

  // // Marshal the message to bytes.
  // final marshaled = message.marshal();
  // print('Marshaled: $marshaled');

  // Unmarshal the bytes back to a message.
  final unmarshaled = HandshakeMessageHelloVerifyRequest.unmarshal(
      raw_hello_verify_request, 0, raw_hello_verify_request.length);
  // print('Unmarshaled: $unmarshaled');
  // print("Cookie got: ${unmarshaled.cookie}");
  // print("Wanted:     $cookie");

  // Verify equality.
  //assert(message == unmarshaled);
  //print('Messages are equal.');
}

final cookie = Uint8List.fromList([
  0x25,
  0xfb,
  0xee,
  0xb3,
  0x7c,
  0x95,
  0xcf,
  0x00,
  0xeb,
  0xad,
  0xe2,
  0xef,
  0xc7,
  0xfd,
  0xbb,
  0xed,
  0xf7,
  0x1f,
  0x6c,
  0xcd,
]);

final raw_hello_verify_request = Uint8List.fromList([
  0xfe,
  0xff,
  0x14,
  0x25,
  0xfb,
  0xee,
  0xb3,
  0x7c,
  0x95,
  0xcf,
  0x00,
  0xeb,
  0xad,
  0xe2,
  0xef,
  0xc7,
  0xfd,
  0xbb,
  0xed,
  0xf7,
  0x1f,
  0x6c,
  0xcd,
]);
