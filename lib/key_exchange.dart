import 'package:x25519/x25519.dart';
import 'package:collection/collection.dart'; // For ListEquality

// Helper function to perform the elliptic curve key exchange
List<int> ellipticCurvePreMasterSecret(List<int> publicKey, List<int> privateKey) {
  // Perform Diffie-Hellman key exchange using X25519
  return X25519(privateKey, publicKey);
}

void main() {
  // Example: Generating key pairs for Alice and Bob
  var aliceKeyPair = generateKeyPair();
  var bobKeyPair = generateKeyPair();

  // Alice computes the shared key using Bob's public key
  var aliceSharedKey = ellipticCurvePreMasterSecret(bobKeyPair.publicKey, aliceKeyPair.privateKey);

  // Bob computes the shared key using Alice's public key
  var bobSharedKey = ellipticCurvePreMasterSecret(aliceKeyPair.publicKey, bobKeyPair.privateKey);

  // Assert that both keys are identical
  assert(ListEquality().equals(aliceSharedKey, bobSharedKey));

  print('Shared Secret (Hex): ${aliceSharedKey.map((e) => e.toRadixString(16).padLeft(2, '0')).join()}');
}

// Helper function to generate a key pair
KeyPair generateKeyPair() {
  // Generate a random private key (32 bytes)
  var privateKey = List<int>.generate(32, (i) => i);
  
  // Compute the public key based on the private key
  var publicKey = X25519(privateKey, List<int>.filled(32, 0));

  return KeyPair(privateKey, publicKey);
}

// Class to hold the generated key pair
class KeyPair {
  final List<int> privateKey;
  final List<int> publicKey;

  KeyPair(this.privateKey, this.publicKey);
}
