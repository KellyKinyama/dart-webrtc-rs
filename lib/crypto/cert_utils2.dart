import 'dart:convert';
import 'package:cryptography/cryptography.dart';

Future<void> generateKeysAndCertificate() async {
  // Use the secp256r1 curve
  final algorithm = Ecdsa.p256(Sha256());

  // Generate the EC key pair
  final keyPair = await algorithm.newKeyPair();
  final keyPairData = await keyPair.extract(); // Extract the key pair details

  final privateKeyBytes = (keyPairData as EcKeyPairData).d;
  final publicKeyBytes = keyPairData.publicKey.x! +
      keyPairData.publicKey.y!; // Concatenate X and Y coordinates
  // Encode private and public keys to PEM-like format
  final privateKeyPem = _encodePem("EC PRIVATE KEY", privateKeyBytes);
  final publicKeyPem = _encodePem("PUBLIC KEY", publicKeyBytes);

  // Print results
  print('Private Key (PEM):\n$privateKeyPem');
  print('Public Key (PEM):\n$publicKeyPem');

  // Print raw byte arrays
  print('Private Key (Bytes): $privateKeyBytes');
  print('Public Key (Bytes): $publicKeyBytes');
}

/// Helper function to encode bytes to a PEM-like format
String _encodePem(String label, List<int> bytes) {
  final base64String = base64.encode(bytes);
  final formattedString = base64String.replaceAllMapped(
      RegExp(r".{1,64}"), (match) => '${match.group(0)}\n');
  return '-----BEGIN $label-----\n$formattedString-----END $label-----';
}

void main() {
  generateKeysAndCertificate();
}
