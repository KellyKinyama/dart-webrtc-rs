import 'dart:typed_data';

import '../record_layer_header.dart';

class ChangeCipherSpec {
  ContentType get contentType => ContentType.ChangeCipherSpec;

  int get size => 1;

  Future<void> marshal(ByteSink writer) async {
    await writer.add(Uint8List.fromList([0x01]));
    await writer.flush();
  }

  static Future<ChangeCipherSpec> unmarshal(ByteReader reader) async {
    final data = await reader.readByte();
    if (data != 0x01) {
      throw ('Invalid Cipher Spec');
    }
    return ChangeCipherSpec();
  }

  static (ChangeCipherSpec, int, bool?) decode(
      Uint8List buf, int offset, int arrayLen) {
    return (ChangeCipherSpec(), buf[offset], null);
  }
}

class ByteReader {
  // Define how you read bytes from the input, e.g., reading from a stream or file
  Future<int> readByte() async {
    // Implement reading logic
    return 0;
  }
}

class ByteSink {
  // Define how you write bytes to the output, e.g., to a file or stream
  Future<void> add(Uint8List data) async {
    // Implement writing logic
  }

  Future<void> flush() async {
    // Implement flush logic
  }
}

// class ContentType {
//   static const changeCipherSpec = ContentType._(20);

//   final int value;
//   const ContentType._(this.value);
// }
