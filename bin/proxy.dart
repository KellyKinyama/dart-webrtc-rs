import 'dart:io';

import 'package:webrtc_rs/dtls_message.dart';
import 'package:webrtc_rs/handshake/certificate.dart';
import 'package:webrtc_rs/handshake/client_hello.dart';
import 'package:webrtc_rs/handshake/server_key_exchange.dart';
import 'package:webrtc_rs/handshake/hello_verify_request.dart';
import 'package:webrtc_rs/handshake_context.dart';
import 'package:webrtc_rs/handshake_manager.dart';
// import 'package:webrtc_rs/handshaker/psk.dart';

void main(List<String> arguments) {
  String ip = "127.0.0.1";
  int port = 4444;
  RawDatagramSocket.bind(InternetAddress(ip), port)
      .then((RawDatagramSocket socket) {
    //print('UDP Echo ready to receive');
    print('listening on udp:${socket.address.address}:${socket.port}');

    late int client;

    //HandshakeManager handshakeManager = HandshakeManager(socket);

    socket.listen((RawSocketEvent e) {
      Datagram? d = socket.receive();

      if (d != null) {
        //handshakeManager.port = d.port;
        //print("recieved data ... from => ip:${d.address.address}:${d.port}");
        final dtlsMsg =
            DecodeDtlsMessageResult.decode(context, d.data, 0, d.data.length);
        //print("DTLS msg: $dtlsMsg");

        // if (d.port != 5555) {
        //   client = d.port;
        //   socket.send(d.data, InternetAddress("127.0.0.1"), 5555);
        // } else {
        //   socket.send(d.data, InternetAddress("127.0.0.1"), d.port);
        // }

        // if (d.port == 5555) {
        //   socket.send(d.data, InternetAddress("127.0.0.1"), client);
        // }
        if (d.port != 5555) {
          client = d.port;
          print("Sending data ... to => ip:${d.address.address}:${d.port}");
          socket.send(d.data, d.address, 5555);
        } else {
          print("Sending data ... to => ip:${d.address.address}:${d.port}");

          var (msg, _, _) = dtlsMsg.message;

          switch (msg.runtimeType) {
            case HandshakeMessageCertificate:
              print("Certificate: ${d.data}");
            case HandshakeMessageServerKeyExchange:
              print("Server key exchange: ${d.data}");
          }

          socket.send(d.data, d.address, client);
        }
      }
    });
  });
}
