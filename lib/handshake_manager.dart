import 'dart:io';
import 'dart:typed_data';

import 'package:webrtc_rs/handshake/certificate.dart';
import 'package:webrtc_rs/handshake/certificate_request.dart';
import 'package:webrtc_rs/handshake/client_hello.dart';
import 'package:webrtc_rs/handshake/server_hello.dart';
import 'package:webrtc_rs/handshake/server_key_exchange.dart';
import 'package:webrtc_rs/record_layer_header.dart';

import 'dtls_message.dart';
import 'handshake/handshake_header.dart';
import 'handshake/handshake_random.dart';
import 'handshake/hello_verify_request.dart';
import 'handshake/server_hello_done.dart';
import 'handshake_context.dart';
import 'dart:math' as dmath;

import 'key_exchange_example.dart';

HandshakeContext context = HandshakeContext();

class HandshakeManager {
  RawDatagramSocket socket;
  late int port;

  HandshakeManager(this.socket);
  void processDtlsMessage(Uint8List data) {
    final dtlsMsg =
        DecodeDtlsMessageResult.decode(context, data, 0, data.length);

    var (msg, _, _) = dtlsMsg.message;

    switch (msg.runtimeType) {
      case HandshakeMessageClientHello:
        final (message, _, _) =
            dtlsMsg.message; // as HandshakeMessageClientHello;
        // print("DTLS msg: ${message}");
        print("Context flight: ${context.flight}");
        context.handshakeMessagesReceived[HandshakeType.ClientHello] = message;
        switch (context.flight) {
          case Flight.Flight0:
            //context.setDTLSState(DTLSState.Connecting);
            context.protocolVersion = message.version;
            //print("context protocol version: ${context.protocolVersion}");
            context.cookie = generateDtlsCookie();
            //print("context protocol version: ${context.cookie}");
            context.flight = Flight.Flight2;
            final helloVerifyRequestResponse =
                createDtlsHelloVerifyRequest(context);
            //print("Hello verify request response: $helloVerifyRequestResponse");
            sendMessage(context, helloVerifyRequestResponse);
            return;
          case Flight.Flight2:
            {
              if (message.cookie.isEmpty) {
                context.flight = Flight.Flight0;
                //print("Empty cookie: ${message.cookie}");
                //context.setDTLSState(DTLSState.Connecting);
                context.protocolVersion = message.version;
                //print("context protocol version: ${context.protocolVersion}");
                context.cookie = generateDtlsCookie();
                //print("context protocol version: ${context.cookie}");
                context.flight = Flight.Flight2;
                final helloVerifyRequestResponse =
                    createDtlsHelloVerifyRequest(context);
                //print("Hello verify request response: $helloVerifyRequestResponse");
                sendMessage(context, helloVerifyRequestResponse);
              }
              print("Received cookie: ${message.cookie}");

              context.clientRandom = message.random.marshal();
              context.serverRandom =
                  HandshakeRandom.defaultInstance().marshal();

              var keys = generateKeys();
              context.serverPublicKey = keys.publicKey;
              context.serverPrivateKey = keys.privateKey;

              final clientRandomBytes = context.clientRandom;
              final serverRandomBytes = context.serverRandom;

              context.serverKeySignature = generateKeySignature(
				clientRandomBytes,
				serverRandomBytes,
				context.serverPublicKey,
				context.Curve, //x25519
				ServerCertificate.PrivateKey,
				context.CipherSuite.HashAlgorithm);

              final serverHelloResponse = createServerHello();
              sendMessage(context, serverHelloResponse);
              //m.SendMessage(context, &serverHelloResponse)certificateResponse := createDtlsCertificate()
              final certificateResponse = createDtlsCertificate();
              sendMessage(context, certificateResponse);
              final serverKeyExchangeResponse = createDtlsServerKeyExchange();
              sendMessage(context, serverKeyExchangeResponse);
              final certificateRequestResponse = createDtlsCertificateRequest();
              sendMessage(context, certificateRequestResponse);
              final serverHelloDoneResponse = createDtlsServerHelloDone();
              sendMessage(context, serverHelloDoneResponse);
            }
          default:
          //print("Unhandle flight: ${context.flight}");
        }
      default:
        {
          //print("Unhandle Runtime type: ${dtlsMsg.message.runtimeType}");
        }
    }
  }

  Uint8List generateDtlsCookie() {
    final cookie = Uint8List(20);
    final random = dmath.Random.secure();
    for (int i = 0; i < cookie.length; i++) {
      cookie[i] = random.nextInt(256);
    }
    return cookie;
  }

  HandshakeMessageHelloVerifyRequest createDtlsHelloVerifyRequest(
      HandshakeContext context) {
    HandshakeMessageHelloVerifyRequest hvr = HandshakeMessageHelloVerifyRequest(
        version: context.protocolVersion, cookie: generateDtlsCookie());
    // hvr.version = context.protocolVersion;
    // hvr.cookie = context.cookie;
    return hvr;
  }

  // Future<void> sendMessage(HandshakeContext context, dynamic message) async {
  //   print("sending message...");
  //   final Uint8List encodedMessageBody = message.marshal();
  //   final encodedMessage = BytesBuilder();
  //   HandshakeHeader? handshakeHeader;

  //   print("Content type: ${message.getContentType()}");
  //   //print("");
  //   switch (message.getContentType()) {
  //     case ContentType.Handshake:
  //       final handshakeMessage = message;
  //       handshakeHeader = HandshakeHeader(
  //         handshakeType: handshakeMessage.getHandshakeType(),
  //         length: Uint24.fromUInt32(encodedMessageBody.length),
  //         messageSequence: context.serverHandshakeSequenceNumber,
  //         fragmentOffset: Uint24.fromUInt32(0),
  //         fragmentLength: Uint24.fromUInt32(encodedMessageBody.length),
  //       );

  //       final cookie = generateDtlsCookie();
  //       context.increaseServerSequence();
  //       break;
  //     case ContentType.ChangeCipherSpec:
  //       encodedMessage.add(encodedMessageBody);
  //       break;

  //     default:
  //       {
  //         print("Unhandle content type:${message.getContentType()}");
  //       }
  //   }

  //   var (hh, dHHOffset, derr) = HandshakeHeader.unmarshal(
  //       encodedMessage.toBytes(), 0, encodedMessage.toBytes().length);
  //   //print("Unmarshalled: $hh");

  //   final recordHeader = RecordLayerHeader(
  //     contentType: message.getContentType(),
  //     protocolVersion: ProtocolVersion(major: 0xfe, minor: 0xff),
  //     //versionBytes: Uint8List.fromList([0xfe, 0xff]),
  //     epoch: context.serverEpoch,
  //     sequenceNumber: context.serverSequenceNumber,
  //     //intSequenceNumber: 0,
  //     contentLen: encodedMessage.toBytes().length,
  //   );
  //   print("Constructed record header: $recordHeader");

  //   // if (context.serverEpoch > 0) {
  //   //   // Epoch is greater than zero, we should encrypt it.
  //   //   if (context.isCipherSuiteInitialized) {
  //   //     final encryptedMessage =
  //   //         await context.gcm!.encrypt(recordHeader, encodedMessage.toBytes());
  //   //     encodedMessage.clear();
  //   //     encodedMessage.add(encryptedMessage);
  //   //     recordHeader.length = encodedMessage.length;
  //   //   }
  //   // }

  //   final encodedHeader = recordHeader.marshal();
  //   encodedMessage.add(encodedHeader);
  //   var (rh, dOffset, err) = RecordLayerHeader.unmarshal(encodedHeader,
  //       offset: 0, arrayLen: encodedHeader.length);

  //   print("decoded Record header: $rh");

  //   final encodedRecordHeader = BytesBuilder();
  //   encodedRecordHeader.add(encodedHeader);
  //   encodedRecordHeader.add(encodedMessage.toBytes());

  //   // //print("Decoded message: $header");

  //   final decodedMessage = DecodeDtlsMessageResult.decode(context,
  //       encodedRecordHeader.toBytes(), 0, encodedRecordHeader.toBytes().length);
  //   // print("Decoded message: $decodedMessage");

  //   //processIncomingMessage(context, encodedMessage.toBytes());
  //   socket.send(encodedRecordHeader.toBytes(), socket.address, port);
  //   // context.increaseServerSequence();
  // }

  void sendMessage(HandshakeContext context, dynamic message) {
    final Uint8List encodedMessageBody = message.marshal();
    final encodedMessage = BytesBuilder();
    HandshakeHeader handshakeHeader;
    switch (message.getContentType()) {
      case ContentType.Handshake:
        print("message type: ${message.getContentType()}");
        handshakeHeader = HandshakeHeader(
            handshakeType: message.getHandshakeType(),
            length: Uint24.fromUInt32(encodedMessageBody.length),
            messageSequence: context.serverHandshakeSequenceNumber,
            fragmentOffset: Uint24.fromUInt32(0),
            fragmentLength: Uint24.fromUInt32(encodedMessageBody.length));
        context.increaseServerHandshakeSequence();
        final encodedHandshakeHeader = handshakeHeader.marshal();
        encodedMessage.add(encodedHandshakeHeader);
        encodedMessage.add(encodedMessageBody);
    }

    final header = RecordLayerHeader(
        contentType: message.getContentType(),
        protocolVersion: ProtocolVersion(major: 254, minor: 253),
        epoch: context.serverEpoch,
        sequenceNumber: context.serverSequenceNumber,
        contentLen: encodedMessage.toBytes().length);

    final encodedHeader = header.marshal();
    final messageToSend = encodedHeader + encodedMessage.toBytes();
    socket.send(messageToSend, socket.address, port);
    context.increaseServerSequence();
  }

//   func (m *HandshakeManager) SendMessage(context *HandshakeContext, message BaseDtlsMessage) {
// 	encodedMessageBody := message.Encode()
// 	encodedMessage := make([]byte, 0)
// 	var handshakeHeader *HandshakeHeader
// 	switch message.GetContentType() {
// 	case ContentTypeHandshake:
// 		handshakeMessage := message.(BaseDtlsHandshakeMessage)
// 		handshakeHeader = &HandshakeHeader{
// 			HandshakeType:   handshakeMessage.GetHandshakeType(),
// 			Length:          NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
// 			MessageSequence: context.ServerHandshakeSequenceNumber,
// 			FragmentOffset:  NewUint24FromUInt32(0),
// 			FragmentLength:  NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
// 		}
// 		context.IncreaseServerHandshakeSequence()
// 		encodedHandshakeHeader := handshakeHeader.Encode()
// 		encodedMessage = append(encodedMessage, encodedHandshakeHeader...)
// 		encodedMessage = append(encodedMessage, encodedMessageBody...)
// 		context.HandshakeMessagesSent[handshakeMessage.GetHandshakeType()] = encodedMessage
// 	case ContentTypeChangeCipherSpec:
// 		encodedMessage = append(encodedMessage, encodedMessageBody...)
// 	}

// 	sequenceNumber := [6]byte{}
// 	sequenceNumber[len(sequenceNumber)-1] += byte(context.ServerSequenceNumber)
// 	header := &RecordHeader{
// 		ContentType:    message.GetContentType(),
// 		Version:        DtlsVersion1_2,
// 		Epoch:          context.ServerEpoch,
// 		SequenceNumber: sequenceNumber,
// 		Length:         uint16(len(encodedMessage)),
// 	}

// 	if context.ServerEpoch > 0 {
// 		// Epoch is greater than zero, we should encrypt it.
// 		if context.IsCipherSuiteInitialized {
// 			encryptedMessage, err := context.GCM.Encrypt(header, encodedMessage)
// 			if err != nil {
// 				panic(err)
// 			}
// 			encodedMessage = encryptedMessage
// 			header.Length = uint16(len(encodedMessage))
// 		}
// 	}

// 	encodedHeader := header.Encode()
// 	encodedMessage = append(encodedHeader, encodedMessage...)

// 	logging.Infof(logging.ProtoDTLS, "Sending message (<u>Flight %d</u>)\n%s\n%s\n%s", context.Flight, header, handshakeHeader, message)
// 	logging.LineSpacer(2)

// 	context.Conn.WriteToUDP(encodedMessage, context.Addr)
// 	context.IncreaseServerSequence()
// }

  HandshakeMessageServerHello createServerHello() {
    final ch = context.handshakeMessagesReceived[HandshakeType.ClientHello]
        as HandshakeMessageClientHello;

    return HandshakeMessageServerHello(
        version: context.protocolVersion,
        random: HandshakeRandom.defaultInstance(),
        sessionId: ch.sessionId,
        cipherSuite: CipherSuiteId.Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        compressionMethod: ch.compressionMethods.ids[0],
        extensions: ch.extensions);
  }

  HandshakeMessageCertificate createDtlsCertificate() {
    final certificate = HandshakeMessageCertificate.unmarshal(raw_certificate);

    //return HandshakeMessageCertificate(certificate: certificate);
    return certificate;
  }

  HandshakeMessageServerKeyExchange createDtlsServerKeyExchange() {
    return HandshakeMessageServerKeyExchange.unmarshal(raw_server_key_exchange);
    // return HandshakeMessageServerKeyExchange(identityHint: identityHint, ellipticCurveType: ellipticCurveType, namedCurve: namedCurve, publicKey: publicKey, algorithm: algorithm, signature: signature)
  }

  HandshakeMessageCertificateRequest createDtlsCertificateRequest() {
    return HandshakeMessageCertificateRequest(certificateTypes: [
      ClientCertificateType.EcdsaSign
    ], signatureHashAlgorithms: [
      SignatureHashAlgorithm(
          hash: HashAlgorithm.Sha256, signature: SignatureAlgorithm.Ecdsa)
    ]);
  }

  HandshakeMessageServerHelloDone createDtlsServerHelloDone() {
    return HandshakeMessageServerHelloDone();
  }
}

final raw_certificate = Uint8List.fromList([
  0x00,
  0x01,
  0x8c,
  0x00,
  0x01,
  0x89,
  0x30,
  0x82,
  0x01,
  0x85,
  0x30,
  0x82,
  0x01,
  0x2b,
  0x02,
  0x14,
  0x7d,
  0x00,
  0xcf,
  0x07,
  0xfc,
  0xe2,
  0xb6,
  0xb8,
  0x3f,
  0x72,
  0xeb,
  0x11,
  0x36,
  0x1b,
  0xf6,
  0x39,
  0xf1,
  0x3c,
  0x33,
  0x41,
  0x30,
  0x0a,
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x04,
  0x03,
  0x02,
  0x30,
  0x45,
  0x31,
  0x0b,
  0x30,
  0x09,
  0x06,
  0x03,
  0x55,
  0x04,
  0x06,
  0x13,
  0x02,
  0x41,
  0x55,
  0x31,
  0x13,
  0x30,
  0x11,
  0x06,
  0x03,
  0x55,
  0x04,
  0x08,
  0x0c,
  0x0a,
  0x53,
  0x6f,
  0x6d,
  0x65,
  0x2d,
  0x53,
  0x74,
  0x61,
  0x74,
  0x65,
  0x31,
  0x21,
  0x30,
  0x1f,
  0x06,
  0x03,
  0x55,
  0x04,
  0x0a,
  0x0c,
  0x18,
  0x49,
  0x6e,
  0x74,
  0x65,
  0x72,
  0x6e,
  0x65,
  0x74,
  0x20,
  0x57,
  0x69,
  0x64,
  0x67,
  0x69,
  0x74,
  0x73,
  0x20,
  0x50,
  0x74,
  0x79,
  0x20,
  0x4c,
  0x74,
  0x64,
  0x30,
  0x1e,
  0x17,
  0x0d,
  0x31,
  0x38,
  0x31,
  0x30,
  0x32,
  0x35,
  0x30,
  0x38,
  0x35,
  0x31,
  0x31,
  0x32,
  0x5a,
  0x17,
  0x0d,
  0x31,
  0x39,
  0x31,
  0x30,
  0x32,
  0x35,
  0x30,
  0x38,
  0x35,
  0x31,
  0x31,
  0x32,
  0x5a,
  0x30,
  0x45,
  0x31,
  0x0b,
  0x30,
  0x09,
  0x06,
  0x03,
  0x55,
  0x04,
  0x06,
  0x13,
  0x02,
  0x41,
  0x55,
  0x31,
  0x13,
  0x30,
  0x11,
  0x06,
  0x03,
  0x55,
  0x04,
  0x08,
  0x0c,
  0x0a,
  0x53,
  0x6f,
  0x6d,
  0x65,
  0x2d,
  0x53,
  0x74,
  0x61,
  0x74,
  0x65,
  0x31,
  0x21,
  0x30,
  0x1f,
  0x06,
  0x03,
  0x55,
  0x04,
  0x0a,
  0x0c,
  0x18,
  0x49,
  0x6e,
  0x74,
  0x65,
  0x72,
  0x6e,
  0x65,
  0x74,
  0x20,
  0x57,
  0x69,
  0x64,
  0x67,
  0x69,
  0x74,
  0x73,
  0x20,
  0x50,
  0x74,
  0x79,
  0x20,
  0x4c,
  0x74,
  0x64,
  0x30,
  0x59,
  0x30,
  0x13,
  0x06,
  0x07,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x02,
  0x01,
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x03,
  0x01,
  0x07,
  0x03,
  0x42,
  0x00,
  0x04,
  0xf9,
  0xb1,
  0x62,
  0xd6,
  0x07,
  0xae,
  0xc3,
  0x36,
  0x34,
  0xf5,
  0xa3,
  0x09,
  0x39,
  0x86,
  0xe7,
  0x3b,
  0x59,
  0xf7,
  0x4a,
  0x1d,
  0xf4,
  0x97,
  0x4f,
  0x91,
  0x40,
  0x56,
  0x1b,
  0x3d,
  0x6c,
  0x5a,
  0x38,
  0x10,
  0x15,
  0x58,
  0xf5,
  0xa4,
  0xcc,
  0xdf,
  0xd5,
  0xf5,
  0x4a,
  0x35,
  0x40,
  0x0f,
  0x9f,
  0x54,
  0xb7,
  0xe9,
  0xe2,
  0xae,
  0x63,
  0x83,
  0x6a,
  0x4c,
  0xfc,
  0xc2,
  0x5f,
  0x78,
  0xa0,
  0xbb,
  0x46,
  0x54,
  0xa4,
  0xda,
  0x30,
  0x0a,
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x04,
  0x03,
  0x02,
  0x03,
  0x48,
  0x00,
  0x30,
  0x45,
  0x02,
  0x20,
  0x47,
  0x1a,
  0x5f,
  0x58,
  0x2a,
  0x74,
  0x33,
  0x6d,
  0xed,
  0xac,
  0x37,
  0x21,
  0xfa,
  0x76,
  0x5a,
  0x4d,
  0x78,
  0x68,
  0x1a,
  0xdd,
  0x80,
  0xa4,
  0xd4,
  0xb7,
  0x7f,
  0x7d,
  0x78,
  0xb3,
  0xfb,
  0xf3,
  0x95,
  0xfb,
  0x02,
  0x21,
  0x00,
  0xc0,
  0x73,
  0x30,
  0xda,
  0x2b,
  0xc0,
  0x0c,
  0x9e,
  0xb2,
  0x25,
  0x0d,
  0x46,
  0xb0,
  0xbc,
  0x66,
  0x7f,
  0x71,
  0x66,
  0xbf,
  0x16,
  0xb3,
  0x80,
  0x78,
  0xd0,
  0x0c,
  0xef,
  0xcc,
  0xf5,
  0xc1,
  0x15,
  0x0f,
  0x58,
]);

final raw_server_key_exchange = Uint8List.fromList([
  0x03,
  0x00,
  0x1d,
  0x41,
  0x04,
  0x0c,
  0xb9,
  0xa3,
  0xb9,
  0x90,
  0x71,
  0x35,
  0x4a,
  0x08,
  0x66,
  0xaf,
  0xd6,
  0x88,
  0x58,
  0x29,
  0x69,
  0x98,
  0xf1,
  0x87,
  0x0f,
  0xb5,
  0xa8,
  0xcd,
  0x92,
  0xf6,
  0x2b,
  0x08,
  0x0c,
  0xd4,
  0x16,
  0x5b,
  0xcc,
  0x81,
  0xf2,
  0x58,
  0x91,
  0x8e,
  0x62,
  0xdf,
  0xc1,
  0xec,
  0x72,
  0xe8,
  0x47,
  0x24,
  0x42,
  0x96,
  0xb8,
  0x7b,
  0xee,
  0xe7,
  0x0d,
  0xdc,
  0x44,
  0xec,
  0xf3,
  0x97,
  0x6b,
  0x1b,
  0x45,
  0x28,
  0xac,
  0x3f,
  0x35,
  0x02,
  0x03,
  0x00,
  0x47,
  0x30,
  0x45,
  0x02,
  0x21,
  0x00,
  0xb2,
  0x0b,
  0x22,
  0x95,
  0x3d,
  0x56,
  0x57,
  0x6a,
  0x3f,
  0x85,
  0x30,
  0x6f,
  0x55,
  0xc3,
  0xf4,
  0x24,
  0x1b,
  0x21,
  0x07,
  0xe5,
  0xdf,
  0xba,
  0x24,
  0x02,
  0x68,
  0x95,
  0x1f,
  0x6e,
  0x13,
  0xbd,
  0x9f,
  0xaa,
  0x02,
  0x20,
  0x49,
  0x9c,
  0x9d,
  0xdf,
  0x84,
  0x60,
  0x33,
  0x27,
  0x96,
  0x9e,
  0x58,
  0x6d,
  0x72,
  0x13,
  0xe7,
  0x3a,
  0xe8,
  0xdf,
  0x43,
  0x75,
  0xc7,
  0xb9,
  0x37,
  0x6e,
  0x90,
  0xe5,
  0x3b,
  0x81,
  0xd4,
  0xda,
  0x68,
  0xcd,
]);
