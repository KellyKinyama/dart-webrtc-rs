import 'dart:typed_data';

import 'package:webrtc_rs/handshake_context.dart';

import 'handshake/alert.dart';
import 'handshake/certificate.dart';
import 'handshake/certificate_request.dart';
import 'handshake/certificate_verify.dart';
import 'handshake/change_cipher_spec.dart';
import 'handshake/client_hello.dart';
import 'handshake/client_key_exchange.dart';
import 'handshake/handshake_header.dart';
import 'handshake/hello_verify_request.dart';
import 'handshake/server_hello.dart';
import 'handshake/server_key_exchange.dart';
import 'record_layer_header.dart';

class DtlsErrors {
  static const errIncompleteDtlsMessage =
      'data contains incomplete DTLS message';
  static const errUnknownDtlsContentType =
      'data contains unknown DTLS content type';
  static const errUnknownDtlsHandshakeType =
      'data contains unknown DTLS handshake type';
}

class DecodeDtlsMessageResult {
  final RecordLayerHeader? recordHeader;
  final HandshakeHeader? handshakeHeader;
  final dynamic message;
  final int offset;

  DecodeDtlsMessageResult(
      this.recordHeader, this.handshakeHeader, this.message, this.offset);

  @override
  String toString() {
    // TODO: implement toString
    return "{record header: $recordHeader, handshake header: $handshakeHeader, message: $message}";
  }

  factory DecodeDtlsMessageResult.decode(
      HandshakeContext context, Uint8List buf, int offset, int arrayLen) {
    if (arrayLen < 1) {
      throw ArgumentError(DtlsErrors.errIncompleteDtlsMessage);
    }
    final (header, decodedOffset, err) =
        RecordLayerHeader.unmarshal(buf, offset: offset, arrayLen: arrayLen);

    //print("Record header: $header");

    //print("offset: $offset, decodedOffset: $decodedOffset");
    offset = decodedOffset;

    if (header.epoch < context.clientEpoch) {
      // Ignore incoming message
      //print("Header epock: ${header.epoch}");
      offset += header.contentLen;
      return DecodeDtlsMessageResult(null, null, null, offset);
    }

    context.clientEpoch = header.epoch;

    context.protocolVersion = header.protocolVersion;

    Uint8List? decryptedBytes;
    Uint8List? encryptedBytes;
    if (header.epoch > 0) {
      // Data arrives encrypted, we should decrypt it before.
      // if (context.isCipherSuiteInitialized) {
      //   encryptedBytes = buf.sublist(offset, offset + header.length);
      //   offset += header.length;
      //   decryptedBytes = await context.gcm?.decrypt(header, encryptedBytes);
      // }
    }

    switch (header.contentType) {
      case ContentType.Handshake:
        if (decryptedBytes == null) {
          final offsetBackup = offset;
          final (handshakeHeader, decodedOffset, err) =
              HandshakeHeader.unmarshal(buf, offset, arrayLen);

          //print("handshake header: $handshakeHeader");

          offset = decodedOffset;

          if (handshakeHeader.length.value !=
              handshakeHeader.fragmentLength.value) {
            // Ignore fragmented packets
            //print('Ignore fragmented packets: ${header.contentType}');
            return DecodeDtlsMessageResult(null, null, null, offset);
          }

          final result =
              decodeHandshake(header, handshakeHeader, buf, offset, arrayLen);

          context.handshakeMessagesReceived[handshakeHeader.handshakeType] =
              Uint8List.fromList(buf.sublist(offsetBackup, offset));

          return DecodeDtlsMessageResult(
              header, handshakeHeader, result, offset);
        } else {
          final (handshakeHeader, decodedOffset, err) =
              HandshakeHeader.decode(decryptedBytes, 0, decryptedBytes.length);
          final result = decodeHandshake(header, handshakeHeader,
              decryptedBytes, 0, decryptedBytes.length);

          final copyArray = Uint8List.fromList(decryptedBytes);
          context.handshakeMessagesReceived[handshakeHeader.handshakeType] =
              copyArray;

          return DecodeDtlsMessageResult(
              header, handshakeHeader, result, offset);
        }
      case ContentType.ChangeCipherSpec:
        final changeCipherSpec = ChangeCipherSpec();
        offset = ChangeCipherSpec.decode(buf, offset, arrayLen);
        return DecodeDtlsMessageResult(header, null, changeCipherSpec, offset);
      case ContentType.Alert:
        Alert alert;
        if (decryptedBytes == null) {
          var (decodedAlert, decodedOffset, err) =
              Alert.decode(buf, offset, arrayLen);
          alert = decodedAlert;
        } else {
          alert = Alert.decode(decryptedBytes, 0, decryptedBytes.length);
        }

        //context.serverSequenceNumber = 0;
        //context.flight = Flight.Flight0;
        return DecodeDtlsMessageResult(header, null, alert, offset);
      default:
        throw ArgumentError(DtlsErrors.errUnknownDtlsContentType);
    }
  }
}

dynamic decodeHandshake(RecordLayerHeader header,
    HandshakeHeader handshakeHeader, Uint8List buf, int offset, int arrayLen) {
  // late BaseDtlsMessage result;
  dynamic result;
  switch (handshakeHeader.handshakeType) {
    case HandshakeType.ClientHello:
      result = HandshakeMessageClientHello.unmarshal(buf, offset, arrayLen);
      break;
    case HandshakeType.HelloVerifyRequest:
      result =
          HandshakeMessageHelloVerifyRequest.unmarshal(buf, offset, arrayLen);
      break;
    case HandshakeType.ServerHello:
      result = HandshakeMessageServerHello.decode(buf, offset, arrayLen);
      break;
    case HandshakeType.Certificate:
      result = HandshakeMessageCertificate.decode(buf, offset, arrayLen);
      break;
    case HandshakeType.ServerKeyExchange:
      result = HandshakeMessageServerKeyExchange.decode(buf, offset, arrayLen);
      break;
    case HandshakeType.CertificateRequest:
      result = HandshakeMessageCertificateRequest.decode(buf, offset, arrayLen);
      break;
    // case HandshakeType.ServerHelloDone:
    //   result = HandshakeMessageServerHelloDone(;
    //   break;
    case HandshakeType.ClientKeyExchange:
      result = HandshakeMessageClientKeyExchange.decode(buf, offset, arrayLen);
      break;
    case HandshakeType.CertificateVerify:
      result = HandshakeMessageCertificateVerify.decode(buf, offset, arrayLen);
      break;
    // case HandshakeType.Finished:
    //   result = HandshakeMessageFinished();
    //   break;
    default:
      print("Unkown handshake type: ${handshakeHeader.handshakeType}");
      throw ArgumentError(DtlsErrors.errUnknownDtlsHandshakeType);
  }
  // var (decodeOffset, err) = result.decode(buf, offset, arrayLen);
  return result;
}

void main() {
  HandshakeContext context = HandshakeContext();
  final dtlsMsg =
      DecodeDtlsMessageResult.decode(context, rawDtlsMsg, 0, rawDtlsMsg.length);
  print("DTLS msg: $dtlsMsg");
}

final rawDtlsMsg = Uint8List.fromList([
  22,
  254,
  253,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  39,
  0,
  127,
  1,
  0,
  0,
  115,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  115,
  254,
  253,
  103,
  146,
  42,
  71,
  152,
  94,
  17,
  98,
  238,
  96,
  121,
  212,
  84,
  208,
  209,
  7,
  127,
  234,
  186,
  105,
  152,
  213,
  72,
  209,
  201,
  212,
  153,
  102,
  93,
  138,
  166,
  111,
  0,
  0,
  0,
  8,
  192,
  43,
  192,
  10,
  192,
  47,
  192,
  20,
  1,
  0,
  0,
  65,
  0,
  13,
  0,
  16,
  0,
  14,
  4,
  3,
  5,
  3,
  6,
  3,
  4,
  1,
  5,
  1,
  6,
  1,
  8,
  7,
  255,
  1,
  0,
  1,
  0,
  0,
  10,
  0,
  8,
  0,
  6,
  0,
  23,
  0,
  29,
  0,
  24,
  0,
  11,
  0,
  2,
  1,
  0,
  0,
  23,
  0,
  0,
  0,
  0,
  0,
  14,
  0,
  12,
  0,
  0,
  9,
  108,
  111,
  99,
  97,
  108,
  104,
  111,
  115,
  116
]);
