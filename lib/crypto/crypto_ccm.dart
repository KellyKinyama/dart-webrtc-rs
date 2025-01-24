import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

const int CRYPTO_CCM_8_TAG_LENGTH = 8;
const int CRYPTO_CCM_TAG_LENGTH = 16;
const int CRYPTO_CCM_NONCE_LENGTH = 12;
const int RECORD_LAYER_HEADER_SIZE = 5; // Adjust as necessary

class CryptoCcm {
  final _AesCcm localCcm;
  final _AesCcm remoteCcm;
  final List<int> localWriteIv;
  final List<int> remoteWriteIv;
  final List<int> localWriteKey;
  final List<int> remoteWriteKey;

  CryptoCcm({
    required List<int> localKey,
    required List<int> localWriteIv,
    required List<int> remoteKey,
    required List<int> remoteWriteIv,
    required _AesCcm localCcm,
    required _AesCcm remoteCcm,
  })  : localCcm = localCcm,
        remoteCcm = remoteCcm,
        localWriteIv = List.from(localWriteIv),
        remoteWriteIv = List.from(remoteWriteIv),
        localWriteKey = List.from(localKey),
        remoteWriteKey = List.from(remoteKey);

  factory CryptoCcm.newInstance(
    CryptoCcmTagLen tagLen,
    List<int> localKey,
    List<int> localWriteIv,
    List<int> remoteKey,
    List<int> remoteWriteIv,
  ) {
    final key = Uint8List.fromList(localKey);
    final localCcm = tagLen == CryptoCcmTagLen.cryptoCcmTagLength
        ? _AesCcm(AESFastEngine(), CRYPTO_CCM_TAG_LENGTH)
        : _AesCcm(AESFastEngine(), CRYPTO_CCM_8_TAG_LENGTH);

    final remoteCcm = tagLen == CryptoCcmTagLen.cryptoCcmTagLength
        ? _AesCcm(AESFastEngine(), CRYPTO_CCM_TAG_LENGTH)
        : _AesCcm(AESFastEngine(), CRYPTO_CCM_8_TAG_LENGTH);

    return CryptoCcm(
      localKey: localKey,
      localWriteIv: localWriteIv,
      remoteKey: remoteKey,
      remoteWriteIv: remoteWriteIv,
      localCcm: localCcm,
      remoteCcm: remoteCcm,
    );
  }

  List<int> encrypt(List<int> pktRlh, List<int> raw) {
    final payload = raw.sublist(RECORD_LAYER_HEADER_SIZE);
    final header = raw.sublist(0, RECORD_LAYER_HEADER_SIZE);

    final nonce = List<int>.filled(CRYPTO_CCM_NONCE_LENGTH, 0);
    nonce.setRange(0, 4, localWriteIv.sublist(0, 4));
    final rng = Random.secure();
    for (int i = 4; i < CRYPTO_CCM_NONCE_LENGTH; i++) {
      nonce[i] = rng.nextInt(256);
    }

    final additionalData = generateAeadAdditionalData(pktRlh, payload.length);

    final buffer = List<int>.from(payload);

    localCcm.encrypt(nonce, additionalData, buffer);

    final result = List<int>.from(header)
      ..addAll(nonce.sublist(4))
      ..addAll(buffer);

    final rLen = (result.length - RECORD_LAYER_HEADER_SIZE) as int;
    final lenBytes = Uint8List(2)
      ..buffer.asByteData().setInt16(0, rLen, Endian.big);
    result.setRange(
        RECORD_LAYER_HEADER_SIZE - 2, RECORD_LAYER_HEADER_SIZE, lenBytes);

    return result;
  }

  List<int> decrypt(List<int> r) {
    final h = RecordLayerHeader.unmarshal(r);
    if (h.contentType == ContentType.changeCipherSpec) {
      return List.from(r);
    }

    if (r.length <= (RECORD_LAYER_HEADER_SIZE + 8)) {
      throw ('Not enough room for nonce');
    }

    final nonce = List<int>.from(remoteWriteIv.sublist(0, 4))
      ..addAll(
          r.sublist(RECORD_LAYER_HEADER_SIZE, RECORD_LAYER_HEADER_SIZE + 8));

    final out = r.sublist(RECORD_LAYER_HEADER_SIZE + 8);

    final buffer = List<int>.from(out);

    remoteCcm.decrypt(nonce, buffer);

    final d = List<int>.from(r.sublist(0, RECORD_LAYER_HEADER_SIZE))
      ..addAll(buffer);
    return d;
  }

  // Method to generate AEAD additional data
  List<int> generateAeadAdditionalData(List<int> pktRlh, int payloadLength) {
    // Implement the additional data generation as needed
    return Uint8List(0);
  }
}

class _AesCcm {
  final AESFastEngine engine;
  final int tagLength;

  _AesCcm(this.engine, this.tagLength);

  void encrypt(List<int> nonce, List<int> additionalData, List<int> buffer) {
    // Implement the encryption logic here
    // You would use `engine` with nonce and additionalData to encrypt `buffer`
  }

  void decrypt(List<int> nonce, List<int> buffer) {
    // Implement the decryption logic here
    // You would use `engine` with nonce to decrypt `buffer`
  }
}

class RecordLayerHeader {
  final ContentType contentType;

  RecordLayerHeader(this.contentType);

  static RecordLayerHeader unmarshal(List<int> data) {
    // Implement unmarshal logic
    return RecordLayerHeader(ContentType.invalid);
  }
}

class ContentType {
  static const changeCipherSpec = ContentType._(20);
  static const invalid = ContentType._(0);

  final int value;

  const ContentType._(this.value);
}

enum CryptoCcmTagLen {
  cryptoCcmTagLength,
  cryptoCcm8TagLength,
}
