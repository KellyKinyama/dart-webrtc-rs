import 'dart:typed_data';

import 'package:webrtc_rs/handshake/handshake_header.dart';

import 'handshake/handshake_random.dart';

enum Flight {
  Flight0,
  Flight2,
  Flight4,
  Flight6,
}

class HandshakeContext {
  int clientEpoch = 0;

  var protocolVersion;

  bool isCipherSuiteInitialized = false;

  Map<HandshakeType, dynamic> handshakeMessagesReceived = {};

  Flight flight = Flight.Flight0;

  Uint8List cookie = Uint8List(0);

  int serverEpoch = 0;

  int serverSequenceNumber = 0;

  int serverHandshakeSequenceNumber = 0;

  late Uint8List serverPublicKey;

  late Uint8List serverPrivateKey;

  late Uint8List serverRandom;

  late Uint8List clientRandom;

  void increaseServerSequence() {
    serverSequenceNumber++;
  }

  void increaseServerHandshakeSequence() {
    serverHandshakeSequenceNumber++;
  }
}
