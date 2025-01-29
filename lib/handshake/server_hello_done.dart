import 'dart:typed_data';

import '../record_layer_header.dart';
import 'handshake_header.dart';

class HandshakeMessageServerHelloDone {
  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHelloDone;
  }

  Uint8List marshal() {
    return Uint8List(0);
  }

  static (HandshakeMessageServerHelloDone, int, bool?) unmarshal(
      Uint8List buf, int offset, int arrayLen) {
    return (HandshakeMessageServerHelloDone(), offset, null);
  }
}
