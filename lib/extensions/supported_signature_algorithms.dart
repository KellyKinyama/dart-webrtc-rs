// import 'dart:typed_data';

// const int EXTENSION_SUPPORTED_SIGNATURE_ALGORITHMS_HEADER_SIZE = 6;

// enum ExtensionValue {
//   supportedSignatureAlgorithms,
// }

// class SignatureHashAlgorithm {
//   int hash;
//   int signature;

//   SignatureHashAlgorithm({required this.hash, required this.signature});
// }

// class ExtensionSupportedSignatureAlgorithms {
//   List<SignatureHashAlgorithm> signatureHashAlgorithms;

//   ExtensionSupportedSignatureAlgorithms(
//       {required this.signatureHashAlgorithms});

//   // Returns the extension value
//   int extensionValue() {
//     return ExtensionValue.supportedSignatureAlgorithms.index;
//   }

//   // Returns the size of the ExtensionSupportedSignatureAlgorithms structure
//   int size() {
//     return 2 + 2 + signatureHashAlgorithms.length * 2;
//   }

//   // Serialize the object to bytes
//   void marshal(ByteData writer) {
//     writer.setUint16(0, 2 + 2 * signatureHashAlgorithms.length, Endian.big);
//     writer.setUint16(2, 2 * signatureHashAlgorithms.length, Endian.big);

//     int offset = 4;
//     for (var v in signatureHashAlgorithms) {
//       writer.setUint8(offset, v.hash);
//       writer.setUint8(offset + 1, v.signature);
//       offset += 2;
//     }
//   }

//   // Deserialize from bytes
//   static ExtensionSupportedSignatureAlgorithms unmarshal(Uint8List bytes) {
//     if (bytes.length < EXTENSION_SUPPORTED_SIGNATURE_ALGORITHMS_HEADER_SIZE) {
//       throw FormatException(
//           "Invalid ExtensionSupportedSignatureAlgorithms data");
//     }

//     int algorithmCount = (bytes[2] << 8 | bytes[3]) ~/ 2;
//     List<SignatureHashAlgorithm> signatureHashAlgorithms = [];

//     int offset = 4;
//     for (int i = 0; i < algorithmCount; i++) {
//       int hash = bytes[offset];
//       int signature = bytes[offset + 1];
//       signatureHashAlgorithms
//           .add(SignatureHashAlgorithm(hash: hash, signature: signature));
//       offset += 2;
//     }

//     return ExtensionSupportedSignatureAlgorithms(
//         signatureHashAlgorithms: signatureHashAlgorithms);
//   }

//   @override
//   String toString() {
//     return 'ExtensionSupportedSignatureAlgorithms(signatureHashAlgorithms: $signatureHashAlgorithms)';
//   }
// }

// void main() {
//   // Example usage

//   // Create a list of SignatureHashAlgorithms
//   final algorithms = [
//     SignatureHashAlgorithm(hash: 0x01, signature: 0x02),
//     SignatureHashAlgorithm(hash: 0x03, signature: 0x04),
//   ];

//   final extension = ExtensionSupportedSignatureAlgorithms(
//       signatureHashAlgorithms: algorithms);
//   //print('ExtensionSupportedSignatureAlgorithms: $extension');

//   // Serialize to bytes
//   final buffer = ByteData(extension.size());
//   extension.marshal(buffer);

//   // Deserialize from bytes
//   final serializedBytes = buffer.buffer.asUint8List();
//   final deserialized =
//       ExtensionSupportedSignatureAlgorithms.unmarshal(serializedBytes);
//   //print('Deserialized ExtensionSupportedSignatureAlgorithms: $deserialized');
// }
