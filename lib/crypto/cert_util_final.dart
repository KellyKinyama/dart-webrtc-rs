import 'package:basic_utils/basic_utils.dart';

final cert = """-----BEGIN CERTIFICATE-----
MIICZDCCAgqgAwIBAgIUSYr0ahwK6h8/kk2u+99h+KOFwWowCgYIKoZIzj0EAwIw
gYgxCzAJBgNVBAYTAnptMQ8wDQYDVQQIDAZ6YW1iaWExDzANBgNVBAcMBmx1c2Fr
YTEOMAwGA1UECgwFemVzY28xDDAKBgNVBAsMA2lzZDEUMBIGA1UEAwwLc2VsZi1z
aWduZWQxIzAhBgkqhkiG9w0BCQEWFGtraW55YW1hQHplc2NvLmNvLnptMB4XDTI1
MDEyODExNTEzNVoXDTI2MDEyODExNTEzNVowgYgxCzAJBgNVBAYTAnptMQ8wDQYD
VQQIDAZ6YW1iaWExDzANBgNVBAcMBmx1c2FrYTEOMAwGA1UECgwFemVzY28xDDAK
BgNVBAsMA2lzZDEUMBIGA1UEAwwLc2VsZi1zaWduZWQxIzAhBgkqhkiG9w0BCQEW
FGtraW55YW1hQHplc2NvLmNvLnptMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEDxtD
onMyuCmQG+22oZ9cG+qCvubBxInwBuvqt+T8t31TRUeFWmwqDUPvgfyXdOKShnw1
Q5VTgdZ9yJU9j3Yxv6NTMFEwHQYDVR0OBBYEFBhrKLlCWl9u7DtnspbwcYLNtz9D
MB8GA1UdIwQYMBaAFBhrKLlCWl9u7DtnspbwcYLNtz9DMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIgPkmNWnoMeD5vr+83yfkFS+Tv4shGVoyjk3m5
NJ3mDc8CIQDK8h0fzGGuoLOrHXb4fnjB9N3gb5srdLC4bgQeLBOLcw==
-----END CERTIFICATE-----""";

final privkey = """-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAHy1W7xHYewI4XMSyKZF27ylVz2HLJsZY2D4gmXiGNxoAcGBSuBBAAK
oUQDQgAEDxtDonMyuCmQG+22oZ9cG+qCvubBxInwBuvqt+T8t31TRUeFWmwqDUPv
gfyXdOKShnw1Q5VTgdZ9yJU9j3Yxvw==
-----END EC PRIVATE KEY-----
""";

void main() {
  X509CertificateData parsedPEM = X509Utils.x509CertificateFromPem(cert);
  //print("certificate: $parsedPEM");

  print("certificate: ${parsedPEM.tbsCertificate?.subjectPublicKeyInfo.bytes}");

  CryptoUtils.ecPrivateKeyFromPem(privkey);
}
