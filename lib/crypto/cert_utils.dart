import 'package:basic_utils/basic_utils.dart';

String generateSelfSignedCertificate() {
  var pair = CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as ECPrivateKey;
  var pubKey = pair.publicKey as ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
}

void main() {
  print(generateSelfSignedCertificate());
}
