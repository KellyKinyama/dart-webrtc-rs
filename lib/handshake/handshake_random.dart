import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'package:collection/collection.dart';

const int RANDOM_BYTES_LENGTH = 28;
const int HANDSHAKE_RANDOM_LENGTH = RANDOM_BYTES_LENGTH + 4;

class HandshakeRandom {
  DateTime gmtUnixTime;
  List<int> randomBytes;

  /// Default constructor
  HandshakeRandom({DateTime? gmtUnixTime, List<int>? randomBytes})
      : gmtUnixTime = gmtUnixTime ?? DateTime.fromMillisecondsSinceEpoch(0),
        randomBytes = randomBytes ?? List.filled(RANDOM_BYTES_LENGTH, 0);

  /// Factory constructor to create a default instance
  factory HandshakeRandom.defaultInstance() {
    return HandshakeRandom(
      gmtUnixTime: DateTime.fromMillisecondsSinceEpoch(0),
      randomBytes: List.filled(RANDOM_BYTES_LENGTH, 0),
    );
  }

  /// Get the size of the structure
  static int size() {
    return HANDSHAKE_RANDOM_LENGTH;
  }

  /// Marshal the object into bytes
  Uint8List marshal() {
    final bb = BytesBuilder();
    int secs = gmtUnixTime.millisecondsSinceEpoch ~/ 1000;
    bb.add(Uint8List(4)..buffer.asByteData().setUint32(0, secs, Endian.big));
    bb.add(Uint8List.fromList(randomBytes));
    return bb.toBytes();
  }

  /// Unmarshal the object from bytes
  static HandshakeRandom unmarshal(Uint8List bytes) {
    // if (bytes.length != HANDSHAKE_RANDOM_LENGTH) {
    //   throw FormatException("Invalid HandshakeRandom length");
    // }

    final secs = ByteData.sublistView(bytes, 0, 4).getUint32(0, Endian.big);
    final gmtUnixTime =
        DateTime.fromMillisecondsSinceEpoch(secs * 1000, isUtc: true);
    final randomBytes = bytes.sublist(4, HANDSHAKE_RANDOM_LENGTH);

    return HandshakeRandom(
      gmtUnixTime: gmtUnixTime,
      randomBytes: randomBytes,
    );
  }

  /// Populate the random bytes and set the current time
  void populate() {
    gmtUnixTime = DateTime.now().toUtc();
    final rng = Random.secure();
    randomBytes = List.generate(RANDOM_BYTES_LENGTH, (_) => rng.nextInt(256));
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HandshakeRandom &&
          runtimeType == other.runtimeType &&
          gmtUnixTime == other.gmtUnixTime &&
          const ListEquality().equals(randomBytes, other.randomBytes);

  @override
  int get hashCode =>
      gmtUnixTime.hashCode ^ const ListEquality().hash(randomBytes);

  @override
  String toString() {
    return 'HandshakeRandom(gmtUnixTime: $gmtUnixTime, randomBytes: $randomBytes)';
  }
}

void main() {
  // Example usage
  final handshakeRandom = HandshakeRandom.defaultInstance();
  //print('Default instance: $handshakeRandom');

  // Populate the instance
  handshakeRandom.populate();
  //print('Populated instance: $handshakeRandom');

  // Serialize to bytes
  final serialized = handshakeRandom.marshal();
  //print('Serialized bytes: $serialized');

  // Deserialize from bytes
  final deserialized = HandshakeRandom.unmarshal(serialized);
  //print('Deserialized instance: $deserialized');

  //print('Instances are equal: ${handshakeRandom == deserialized}');
}
