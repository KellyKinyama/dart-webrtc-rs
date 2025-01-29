import 'dart:io';

import 'package:webrtc_rs/dtls_message.dart';
import 'package:webrtc_rs/handshake_context.dart';
//import 'package:webrtc_rs/handshaker/psk.dart';
import 'package:webrtc_rs/handshake_manager.dart';

void main(List<String> arguments) {
  String ip = "127.0.0.1";
  int port = 4444;
  RawDatagramSocket.bind(InternetAddress(ip), port)
      .then((RawDatagramSocket socket) {
    //print('UDP Echo ready to receive');
    print('listening on udp:${socket.address.address}:${socket.port}');

    HandshakeManager handshakeManager = HandshakeManager(socket);

    socket.listen((RawSocketEvent e) {
      Datagram? d = socket.receive();

      if (d != null) {
        handshakeManager.port = d.port;
        //print("recieved data ...");
        HandshakeContext context = HandshakeContext();
        // final dtlsMsg =
        //     DecodeDtlsMessageResult.decode(context, d.data, 0, d.data.length);

        handshakeManager.processDtlsMessage(d.data);
        //print("DTLS msg: $dtlsMsg");
      }
    });
  });
}
