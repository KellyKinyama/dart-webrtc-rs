import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

void convertPemToDer(String pemFilePath, String derFilePath) {
  // Read the PEM file
  String pem = File(pemFilePath).readAsStringSync().trim();

  // Extract the Base64 content
  final match = RegExp(
    r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
    caseSensitive: false,
    dotAll: true,
  ).firstMatch(pem);

  if (match == null) {
    throw FormatException('Invalid PEM format or missing certificate block.');
  }

  // Decode Base64 to get DER bytes
  Uint8List derBytes =
      base64Decode(match.group(1)!.replaceAll(RegExp(r'\s+'), ''));

  print("Der: $derBytes");

  // Write DER bytes to file
  File(derFilePath).writeAsBytesSync(derBytes);

  print('Converted PEM to DER: $derFilePath');
}

void main() {
  String pemFilePath =
      'C:/www/dart/webrtc-rs/certs/server.pem'; // Input PEM file
  String derFilePath =
      'C:/www/dart/webrtc-rs/certs/certificate.der'; // Output DER file

  try {
    convertPemToDer(pemFilePath, derFilePath);
  } catch (e) {
    print('Error: $e');
  }
}
