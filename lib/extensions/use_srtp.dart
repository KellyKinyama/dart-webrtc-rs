import 'dart:typed_data';
import 'dart:io';

enum SrtpProtectionProfile {
  srtpAes128CmHmacSha180(0x0001),
  srtpAes128CmHmacSha132(0x0002),
  srtpAeadAes128Gcm(0x0007),
  srtpAeadAes256Gcm(0x0008),
  unsupported(-1);

  final int value;

  const SrtpProtectionProfile(this.value);

  // Convert a u16 value to an SrtpProtectionProfile
  factory SrtpProtectionProfile.from(int val) {
    switch (val) {
      case 0x0001:
        return SrtpProtectionProfile.srtpAes128CmHmacSha180;
      case 0x0002:
        return SrtpProtectionProfile.srtpAes128CmHmacSha132;
      case 0x0007:
        return SrtpProtectionProfile.srtpAeadAes128Gcm;
      case 0x0008:
        return SrtpProtectionProfile.srtpAeadAes256Gcm;
      default:
        return SrtpProtectionProfile.unsupported;
    }
  }
}

class ExtensionUseSrtp {
  List<SrtpProtectionProfile> protectionProfiles;

  ExtensionUseSrtp({required this.protectionProfiles});

  // Returns the extension value
  int extensionValue() {
    return 0x0015; // The equivalent of ExtensionValue::UseSrtp in Rust
  }

  // Returns the size of the ExtensionUseSrtp structure
  int size() {
    return 2 +
        2 +
        protectionProfiles.length * 2 +
        1; // Fixed and calculated parts
  }

  // Serialize the object to bytes
  // void marshal(ByteData writer) {
  //   writer.setUint16(
  //       0, 2 + 1 + 2 * protectionProfiles.length, Endian.big); // Total length
  //   writer.setUint16(2, 2 * protectionProfiles.length,
  //       Endian.big); // Protection profiles length

  //   for (int i = 0; i < protectionProfiles.length; i++) {
  //     writer.setUint16(4 + (i * 2), protectionProfiles[i].value, Endian.big);
  //   }

  //   // MKI Length
  //   writer.setUint8(4 + (protectionProfiles.length * 2), 0x00);
  // }

  // Deserialize from bytes
  // static ExtensionUseSrtp unmarshal(Uint8List bytes) {
  //   if (bytes.length < 6) {
  //     throw FormatException("Invalid ExtensionUseSrtp data");
  //   }

  //   final profileCount = (bytes[2] & 0xFF) ~/ 2;
  //   List<SrtpProtectionProfile> protectionProfiles = [];

  //   for (int i = 0; i < profileCount; i++) {
  //     final profileValue = ByteData.sublistView(bytes, 4 + (i * 2), 6 + (i * 2))
  //         .getUint16(0, Endian.big);
  //     protectionProfiles.add(SrtpProtectionProfile.from(profileValue));
  //   }

  //   return ExtensionUseSrtp(protectionProfiles: protectionProfiles);
  // }
}

// void main() {
//   // Example usage

//   // Create an example ExtensionUseSrtp
//   final extensionUseSrtp = ExtensionUseSrtp(protectionProfiles: [
//     SrtpProtectionProfile.srtpAes128CmHmacSha180,
//     SrtpProtectionProfile.srtpAes128CmHmacSha132,
//   ]);
//   //print('ExtensionUseSrtp: $extensionUseSrtp');

//   // Serialize to bytes
//   final buffer = ByteData(extensionUseSrtp.size());
//   extensionUseSrtp.marshal(buffer);

//   // Deserialize from bytes
//   final serializedBytes = buffer.buffer.asUint8List();
//   final deserialized = ExtensionUseSrtp.unmarshal(serializedBytes);
//   //print('Deserialized ExtensionUseSrtp: $deserialized');
// }
