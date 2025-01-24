import 'dart:typed_data';
import 'dart:convert';

import 'renogotiation_info.dart';
import 'server_name.dart';
import 'supported_elliptic_curves.dart';
import 'supported_point_formats.dart';
import 'supported_signature_algorithms.dart';
import 'use_extended_master_secret.dart';
import 'use_srtp.dart';

enum ExtensionValue {
  serverName,
  supportedEllipticCurves,
  supportedPointFormats,
  supportedSignatureAlgorithms,
  useSrtp,
  useExtendedMasterSecret,
  renegotiationInfo,
  unsupported,
}

enum ExtensionType {
  ServerName(0),
  SupportedEllipticCurves(10),
  SupportedPointFormats(11),
  SupportedSignatureAlgorithms(13),
  UseSRTP(14),
  ALPN(16),
  UseExtendedMasterSecret(23),
  RenegotiationInfo(65281),

  Unknown(65535); //Not a valid value

  final int value;

  const ExtensionType(this.value);

  factory ExtensionType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

extension ExtensionValueExtension on ExtensionValue {
  static ExtensionValue from(int val) {
    switch (val) {
      case 0:
        return ExtensionValue.serverName;
      case 10:
        return ExtensionValue.supportedEllipticCurves;
      case 11:
        return ExtensionValue.supportedPointFormats;
      case 13:
        return ExtensionValue.supportedSignatureAlgorithms;
      case 14:
        return ExtensionValue.useSrtp;
      case 23:
        return ExtensionValue.useExtendedMasterSecret;
      case 65281:
        return ExtensionValue.renegotiationInfo;
      default:
        return ExtensionValue.unsupported;
    }
  }
}

class Extension {
  final dynamic extensionData;

  Extension._(this.extensionData);

  factory Extension.serverName(ExtensionServerName ext) {
    return Extension._(ext);
  }

  factory Extension.supportedEllipticCurves(
      ExtensionSupportedEllipticCurves ext) {
    return Extension._(ext);
  }

  factory Extension.supportedPointFormats(ExtensionSupportedPointFormats ext) {
    return Extension._(ext);
  }

  factory Extension.supportedSignatureAlgorithms(
      ExtensionSupportedSignatureAlgorithms ext) {
    return Extension._(ext);
  }

  factory Extension.useSrtp(ExtensionUseSrtp ext) {
    return Extension._(ext);
  }

  factory Extension.useExtendedMasterSecret(
      ExtensionUseExtendedMasterSecret ext) {
    return Extension._(ext);
  }

  factory Extension.renegotiationInfo(ExtensionRenegotiationInfo ext) {
    return Extension._(ext);
  }

  int extensionValue() {
    if (extensionData is ExtensionServerName) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionSupportedEllipticCurves) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionSupportedPointFormats) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionSupportedSignatureAlgorithms) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionUseSrtp) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionUseExtendedMasterSecret) {
      return extensionData.extensionValue();
    }
    if (extensionData is ExtensionRenegotiationInfo) {
      return extensionData.extensionValue();
    }
    return ExtensionValue.unsupported.index;
  }

  int size() {
    if (extensionData is ExtensionServerName) {
      return extensionData.size();
    }
    if (extensionData is ExtensionSupportedEllipticCurves) {
      return extensionData.size();
    }
    if (extensionData is ExtensionSupportedPointFormats) {
      return extensionData.size();
    }
    if (extensionData is ExtensionSupportedSignatureAlgorithms) {
      return extensionData.size();
    }
    if (extensionData is ExtensionUseSrtp) {
      return extensionData.size();
    }
    if (extensionData is ExtensionUseExtendedMasterSecret) {
      return extensionData.size();
    }
    if (extensionData is ExtensionRenegotiationInfo) {
      return extensionData.size();
    }
    return 0;
  }

  void marshal(ByteData writer) {
    writer.setUint16(0, extensionValue(), Endian.big);
    if (extensionData is ExtensionServerName) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionSupportedEllipticCurves) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionSupportedPointFormats) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionSupportedSignatureAlgorithms) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionUseSrtp) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionUseExtendedMasterSecret) {
      extensionData.marshal(writer);
    }
    if (extensionData is ExtensionRenegotiationInfo) {
      extensionData.marshal(writer);
    }
  }

  static Extension unmarshal(Uint8List bytes) {
    final extensionValue = ExtensionValueExtension.from(bytes[0]);
    switch (extensionValue) {
      case ExtensionValue.serverName:
        return Extension.serverName(ExtensionServerName("server name"));
      case ExtensionValue.supportedEllipticCurves:
        return Extension.supportedEllipticCurves(
            ExtensionSupportedEllipticCurves(ellipticCurves: []));
      case ExtensionValue.supportedPointFormats:
        return Extension.supportedPointFormats(
            ExtensionSupportedPointFormats(pointFormats: []));
      case ExtensionValue.supportedSignatureAlgorithms:
        return Extension.supportedSignatureAlgorithms(
            ExtensionSupportedSignatureAlgorithms(signatureHashAlgorithms: []));
      case ExtensionValue.useSrtp:
        return Extension.useSrtp(ExtensionUseSrtp(protectionProfiles: []));
      case ExtensionValue.useExtendedMasterSecret:
        return Extension.useExtendedMasterSecret(
            ExtensionUseExtendedMasterSecret(supported: true));
      case ExtensionValue.renegotiationInfo:
        return Extension.renegotiationInfo(
            ExtensionRenegotiationInfo(1, renegotiatedConnection: 0));
      default:
        throw FormatException("Unsupported extension type");
    }
  }

  // factory Extension.fromInt(int key) {
  // return values.firstWhere((element) => element.value == key);
  // }

  @override
  String toString() {
    // TODO: implement toString
    return "{Extension: $extensionData}";
  }
}

void main() {
  // Example usage
  final extension = Extension.serverName(ExtensionServerName("server name"));
  // print('Extension size: ${extension.size()}');
}
