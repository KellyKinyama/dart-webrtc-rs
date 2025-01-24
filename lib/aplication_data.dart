// import 'dart:io';
import 'dart:typed_data';

import 'record_layer_header.dart';


class ApplicationData {
  final List<int> data;

  ApplicationData(this.data);

  ContentType get contentType => ContentType.ApplicationData;

  int get size => data.length;

  Future<void> marshal(ByteSink writer) async {
    await writer.add(Uint8List.fromList(data));
    await writer.flush();
  }

  static Future<ApplicationData> unmarshal(ByteReader reader) async {
    final data = await reader.readToEnd();
    return ApplicationData(data);
  }
}

class ByteReader {
  // Define how you read bytes from the input, e.g., reading from a stream or file
  Future<List<int>> readToEnd() async {
    // Implement reading logic
    return [];
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

class Error {
  static final invalidContentType = Exception('Invalid ContentType');
}
