import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

const int CRYPTO_GCM_TAG_LENGTH = 16;
const int CRYPTO_GCM_NONCE_LENGTH = 12;
const int RECORD_LAYER_HEADER_SIZE = 5; // Adjust as necessary

class CryptoGcm {
  final AEADBlockCipher localGcm;
  final AEADBlockCipher remoteGcm;
  final List<int> localWriteIv;
  final List<int> remoteWriteIv;

  CryptoGcm({
    required List<int> localKey,
    required List<int> localWriteIv,
    required List<int> remoteKey,
    required List<int> remoteWriteIv,
  })  : localGcm = GCMBlockCipher(AESFastEngine()),
        remoteGcm = GCMBlockCipher(AESFastEngine()),
        localWriteIv = List.from(localWriteIv),
        remoteWriteIv = List.from(remoteWriteIv) {
    localGcm.init(
        true,
        AEADParameters(
            KeyParameter(Uint8List.fromList(localKey)),
            CRYPTO_GCM_TAG_LENGTH * 8,
            Uint8List.fromList(localWriteIv),
            Uint8List(0)));
    remoteGcm.init(
        false,
        AEADParameters(
            KeyParameter(Uint8List.fromList(remoteKey)),
            CRYPTO_GCM_TAG_LENGTH * 8,
            Uint8List.fromList(remoteWriteIv),
            Uint8List(0)));
  }

  List<int> encrypt(List<int> pktRlh, List<int> raw) {
    final payload = raw.sublist(RECORD_LAYER_HEADER_SIZE);
    final header = raw.sublist(0, RECORD_LAYER_HEADER_SIZE);

    final nonce = List<int>.filled(CRYPTO_GCM_NONCE_LENGTH, 0);
    nonce.setRange(0, 4, localWriteIv.sublist(0, 4));
    final rng = Random.secure();
    for (int i = 4; i < CRYPTO_GCM_NONCE_LENGTH; i++) {
      nonce[i] = rng.nextInt(256);
    }

    final additionalData = generateAeadAdditionalData(pktRlh, payload.length);

    localGcm.init(
        true,
        AEADParameters(
            KeyParameter(Uint8List.fromList(localWriteIv)),
            CRYPTO_GCM_TAG_LENGTH * 8,
            Uint8List.fromList(nonce),
            additionalData));

    final buffer = Uint8List.fromList(payload);
    final cipher = localGcm.process(buffer);

    final result = List<int>.from(header)
      ..addAll(nonce.sublist(4))
      ..addAll(cipher);

    final rLen = result.length - RECORD_LAYER_HEADER_SIZE;
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

    if (r.length <= RECORD_LAYER_HEADER_SIZE + 8) {
      throw ('Not enough room for nonce');
    }

    final nonce = List<int>.from(remoteWriteIv.sublist(0, 4))
      ..addAll(
          r.sublist(RECORD_LAYER_HEADER_SIZE, RECORD_LAYER_HEADER_SIZE + 8));

    final out = r.sublist(RECORD_LAYER_HEADER_SIZE + 8);

    final additionalData =
        generateAeadAdditionalData(h, out.length - CRYPTO_GCM_TAG_LENGTH);

    remoteGcm.init(
        false,
        AEADParameters(
            KeyParameter(Uint8List.fromList(remoteWriteIv)),
            CRYPTO_GCM_TAG_LENGTH * 8,
            Uint8List.fromList(nonce),
            additionalData));

    final buffer = Uint8List.fromList(out);
    final cipher = remoteGcm.process(buffer);

    final d = List<int>.from(r.sublist(0, RECORD_LAYER_HEADER_SIZE))
      ..addAll(cipher);
    return d;
  }

  Uint8List generateAeadAdditionalData(List<int> pktRlh, int payloadLength) {
    // Implement the additional data generation as needed
    return Uint8List(0);
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
