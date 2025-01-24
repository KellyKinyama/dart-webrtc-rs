import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'package:x25519/x25519.dart' as x25519;

import '../handshake/certificate.dart';
import '../handshake/server_key_exchange.dart';

import 'dart:convert'; // For Base64 decoding

({Uint8List privateKey, Uint8List publicKey}) generateKeys() {
  final aliceKeyPair = x25519.generateKeyPair();
  final privKey = Uint8List.fromList(aliceKeyPair.privateKey);
  final pubKey = Uint8List.fromList(aliceKeyPair.publicKey);
  return (privateKey: privKey, publicKey: pubKey);
}

Future<({Uint8List privateKey, Uint8List publicKey})>
    generateEd25519Keys() async {
  final algorithm = cryptography.Ed25519();
  final keyPair = await algorithm.newKeyPair();
  final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
  final publicKey = await keyPair.extractPublicKey();
  return (
    privateKey: Uint8List.fromList(privateKeyBytes),
    publicKey: Uint8List.fromList(publicKey.bytes)
  );
}

Uint8List generateValueKeyMessage(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKey,
  ECCurveType curve,
) {
  ByteData serverECDHParams = ByteData(4);
  serverECDHParams.setUint8(0, curve.value); // Curve type
  serverECDHParams.setUint16(1, NamedCurve.X25519.value); // Curve ID
  serverECDHParams.setUint8(3, publicKey.length); // Public key length

  final bb = BytesBuilder();
  bb.add(clientRandom);
  bb.add(serverRandom);
  bb.add(serverECDHParams.buffer.asUint8List());
  bb.add(publicKey);

  return bb.toBytes();
}

Future<Uint8List> generateKeySignature(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKeyBytes,
  ECCurveType curveValue,
  List<int> privateKeyBytes,
) async {
  // Generate the message to sign
  final msg = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Convert the private key bytes to an Ed25519 private key
  final privateKey = cryptography.SimpleKeyPairData(
    privateKeyBytes,
    publicKey: cryptography.SimplePublicKey(publicKeyBytes,
        type: cryptography.KeyPairType.ed25519),
    type: cryptography.KeyPairType.ed25519,
  );

  // Use Ed25519 to sign the hashed message
  final algorithm = cryptography.Ed25519();
  final signature = await algorithm.sign(hashedMessage, keyPair: privateKey);

  // Return the signature as Uint8List
  return Uint8List.fromList(signature.bytes);
}

Future<bool> verifyKeySignature(
  Uint8List clientRandom,
  Uint8List serverRandom,
  Uint8List publicKeyBytes,
  ECCurveType curveValue,
  Uint8List signatureBytes,
) async {
  // Generate the message to verify
  final msg = generateValueKeyMessage(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
  );

  // Hash the message using SHA-256
  final hashedMessage = sha256.convert(msg).bytes;

  // Convert the public key bytes to an Ed25519 public key object
  final publicKey = cryptography.SimplePublicKey(
    publicKeyBytes,
    type: cryptography.KeyPairType.ed25519,
  );

  // Verify the signature
  final algorithm = cryptography.Ed25519();
  return await algorithm.verify(
    hashedMessage,
    signature: cryptography.Signature(signatureBytes, publicKey: publicKey),
  );
}

// void main() {
//   testCertifcateExample();
// }

// Function to load a PEM certificate
Uint8List loadPEMCertificate(String pem) {
  // Remove the BEGIN/END certificate lines and decode the base64 content
  final cleanPem = pem
      .replaceAll('-----BEGIN CERTIFICATE-----', '')
      .replaceAll('-----END CERTIFICATE-----', '')
      .replaceAll('\n', '');

  // Decode the base64 encoded string
  return base64Decode(cleanPem);
}

void main() {
  // PEM certificate as a string
  String pemCertificate = '''
-----BEGIN CERTIFICATE-----
MIIGxzCCBa+gAwIBAgIQDvmYl5xYU/oi7Rt4KvkygTANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQw
MzEzMDAwMDAwWhcNMjUwMzE0MjM1OTU5WjBOMQswCQYDVQQGEwJaTTEPMA0GA1UE
BxMGTHVzYWthMRYwFAYDVQQKEw1aRVNDTyBMSU1JVEVEMRYwFAYDVQQDDA0qLnpl
c2NvLmNvLnptMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtgPQE7B9
RXAGxe+GziLkfH/+huHDVDWrltJu9NBhCdkosOKXT64/V5NrPExM5E85DsrF6l+Y
NEeGbmlh3hL728dQd1UY475+sMNhpDKLWtaBIP9LmQLi+POGx7ePVsAj5wiWxmY0
Lv+O8WzuQDwLkkEnLhmujmnlKsIshIBgKYkf9VaCvdSclfAUFZaphfxBTyXLc7fE
1ZH2+JtxNIOo18cmrOoc0IrsCRRomDCAcdYbvOMvHqeepLfZ1n01cCnKe1+W+Y5V
cpuCzl/qd5xG4rHbksSGnBeButlRR+Ee5sLyrPPI1Y7jtqZS5TZO/Ayzq6uEBAwN
IDvQ2zhc1TIB1wIDAQABo4IDlDCCA5AwHwYDVR0jBBgwFoAUdIWAwGbH3zfez70p
N6oDHb7tzRcwHQYDVR0OBBYEFPens+aDTKx59v0AsJw/XIEGxVBoMCUGA1UdEQQe
MByCDSouemVzY28uY28uem2CC3plc2NvLmNvLnptMD4GA1UdIAQ3MDUwMwYGZ4EM
AQICMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGf
BgNVHR8EgZcwgZQwSKBGoESGQmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
Q2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNybDBIoEagRIZCaHR0
cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsRzJUTFNSU0FTSEEy
NTYyMDIwQ0ExLTEuY3JsMIGHBggrBgEFBQcBAQR7MHkwJAYIKwYBBQUHMAGGGGh0
dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBRBggrBgEFBQcwAoZFaHR0cDovL2NhY2Vy
dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsRzJUTFNSU0FTSEEyNTYyMDIw
Q0ExLTEuY3J0MAwGA1UdEwEB/wQCMAAwggF8BgorBgEEAdZ5AgQCBIIBbASCAWgB
ZgB2AE51oydcmhDDOFts1N8/Uusd8OCOG41pwLH6ZLFimjnfAAABjjf9QLcAAAQD
AEcwRQIgE+wA/yt8WXoinpp88IVhzqXmPNjdx6EdqwARyJMxhRcCIQCvgkMV2gFW
ZSEAXDi/swT0Teq31jW+wMeUqXzDF0pkbwB1AH1ZHhLheCp7HGFnfF79+NCHXBSg
TpWeuQMv2Q6MLnm4AAABjjf9QPcAAAQDAEYwRAIgaSdv204JL4RgAzb1j5ghHqCH
mHtxFbk8BMPBNY0X6BQCIFrZoDmE0FRqQmBHrcYNBIxY5DJMWCcyG/lXmrYVrZvt
AHUA5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGON/1BIAAABAMA
RjBEAiBfgMSl/qptOtSRmIH9ImVwo7PJD8WA4/K/kL+5EM6KXgIgCHAiIM/2eWds
9CxgYkQE3oqmHxZZ06tFOBo1jzMpIGEwDQYJKoZIhvcNAQELBQADggEBAKDfg5rg
vJchhw7J3C3+3qZB5CXu+FbIW0wvPisOD8DDFWvOm6sQcxnUdUDpCQ6Yk64ce9+m
MhPcZr50sevd46UvExUoJnBc8raR4+Mm21VVekwzfA6ASJa/GX0ixLI/F1MjKb25
C0zEa4ac9xBcYekMtqjr12THsNSC2WM/YSNi6mJLJSBrBvH4gRLYzf5Aram3LSjo
mspuC0OtEwUbxTFTe6dUwbzdy60wbTLmZBdiTKzrrpLqFcnulBRz/cQpbxHrthL0
hGLZojj2j+EpbYqb6ix5Q99948cROaZc4SaiOxYiBf6BDi2foNDNMGjyvsJUHDdn
MZY2srsXEJ5vK3s=
-----END CERTIFICATE-----
  ''';

  // Load and decode the PEM certificate
  Uint8List certificateData = loadPEMCertificate(pemCertificate);

  // Now you can use the certificate data for further processing
  print('Certificate loaded: ${certificateData.length} bytes');
}

void verifyKeySignatureTest() async {
  // Example inputs
  final clientRandom = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final serverRandom = Uint8List.fromList([9, 10, 11, 12, 13, 14, 15, 16]);
  final keys = await generateEd25519Keys();
  final publicKeyBytes = keys.publicKey;
  final privateKeyBytes = keys.privateKey;
  final curveValue = ECCurveType.fromInt(0x03); // Example curve type value

  // Generate a signature
  final algorithm = cryptography.Ed25519();
  final privateKey = cryptography.SimpleKeyPairData(
    privateKeyBytes,
    publicKey: cryptography.SimplePublicKey(publicKeyBytes,
        type: cryptography.KeyPairType.ed25519),
    type: cryptography.KeyPairType.ed25519,
  );

  final msg = generateValueKeyMessage(
      clientRandom, serverRandom, publicKeyBytes, curveValue);
  final hashedMessage = sha256.convert(msg).bytes;
  final signature = await algorithm.sign(hashedMessage, keyPair: privateKey);

  // Verify the signature
  final isValid = await verifyKeySignature(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
    Uint8List.fromList(signature.bytes),
  );

  if (isValid) {
    print('Signature is valid!');
  } else {
    print('Signature is invalid!');
  }
}

void generateKeySignatureExample() async {
  // Example inputs
  final clientRandom = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final serverRandom = Uint8List.fromList([9, 10, 11, 12, 13, 14, 15, 16]);

  // Generate Ed25519 key pair
  final keys = await generateEd25519Keys();
  final publicKeyBytes = keys.publicKey;
  final privateKeyBytes = keys.privateKey;

  final curveValue =
      ECCurveType.fromInt(0x03); // Placeholder curve value for Ed25519

  // Generate the signature
  final signature = await generateKeySignature(
    clientRandom,
    serverRandom,
    publicKeyBytes,
    curveValue,
    privateKeyBytes,
  );

  // Output the signature
  print('Generated Signature: ${signature.toString()}');
}

void testCertifcateExample() {
  // Wrap the certificate in the HandshakeMessageCertificate class
  final handshakeMessage = HandshakeMessageCertificate(
    certificate: [fakeCertificateData], // Add the certificate data as a list
  );

  // Print size of the marshaled certificate
  print('Certificate size: ${handshakeMessage.size()}');

  // Marshal the certificate into a byte array for transmission
  final marshaledCertificate = handshakeMessage.marshal();
  print('Marshalled Certificate: $marshaledCertificate');
}

// Placeholder certificate data (fake certificate for the example)
final fakeCertificateData = base64Decode(
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuK+dW60fpoDMyXTsnGJ+' +
        'ZdDh9nvsFxoNfcsHXAXgETgK2pFkX9QqZPpYMYKqOfA1WkXiy3kkzEjVfAt8Cp/' +
        'ApwlQ1FbYAqS4aAeNhDaM6wrlwlhGVHqH5y7pX0N0iFhwr2xnZ7os+QgyTxv0ddB' +
        'Ez8jrD2hWwBgyOXuMlPTBdMb9mFlzreX9XsMtfxaPeDi9Eddz+i4HDv4+YRxMByl' +
        'o7fiB2CGYglG9lLRWGq9j0RM09xwtylzJACUtgtRIu2gyFdF58fuYndI1kh52yw5' +
        'dU7vSYc+F1T4rWxLgFqfmN4ugXyFxxFgkA6W9tSBDuPRpYOh/ZTrVXkSzcOqsWKm' +
        '5gQ+8wIDAQAB');
