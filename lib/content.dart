import 'dart:typed_data';

// enum ContentType {
//   ChangeCipherSpec(20),
//   Alert(21),
//   Handshake(22),
//   ApplicationData(23),
//   unknown(255);

//   const ContentType(this.value);

//   final int value;

//   factory ContentType.fromInt(int key) {
//     return values.firstWhere((element) => element.value == key);
//   }
// }

// abstract class Content {
//   ContentType get contentType;
//   int get size;
//   void marshal(ByteSink writer);
//   static Future<Content> unmarshal(
//       ContentType contentType, ByteReader reader) async {
//     switch (contentType) {
//       case ContentType.changeCipherSpec:
//         return ChangeCipherSpec.unmarshal(reader);
//       case ContentType.alert:
//         return Alert.unmarshal(reader);
//       case ContentType.handshake:
//         return Handshake.unmarshal(reader);
//       case ContentType.applicationData:
//         return ApplicationData.unmarshal(reader);
//       default:
//         throw Error.invalidContentType;
//     }
//   }
// }

class ByteReader {
  // Define how you read bytes from the input
}

class ByteSink {
  // Define how you write bytes to the output
}

class Error {
  static final invalidContentType = Exception('Invalid ContentType');
}
