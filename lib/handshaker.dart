import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:log/log.dart';

import 'cipher_suite.dart';
import 'config.dart';
import 'conn.dart';
import 'content.dart';
import 'crypto.dart';
import 'error.dart';
import 'extension/extension_use_srtp.dart';
import 'extensions/use_srtp.dart';
import 'handshake/certificate_request.dart';
import 'handshake/client_hello.dart';
import 'signature_hash_algorithm.dart';

class HandshakeState {
  static const Errored = HandshakeState._('Errored');
  static const Preparing = HandshakeState._('Preparing');
  static const Sending = HandshakeState._('Sending');
  static const Waiting = HandshakeState._('Waiting');
  static const Finished = HandshakeState._('Finished');

  final String name;

  const HandshakeState._(this.name);

  @override
  String toString() => name;
}

typedef VerifyPeerCertificateFn = Future<void> Function(
    List<List<int>> peerCertificates, List<int> certs);

class HandshakeConfig {
  final PskCallback? localPskCallback;
  final List<int>? localPskIdentityHint;
  final List<CipherSuiteId> localCipherSuites; // Available CipherSuites
  final List<SignatureHashAlgorithm> localSignatureSchemes; // Available signature schemes
  final ExtendedMasterSecretType extendedMasterSecret; // Policy for the Extended Master Support extension
  final List<SrtpProtectionProfile> localSrtpProtectionProfiles; // Available SRTPProtectionProfiles, if empty no SRTP support
  final String serverName;
  final ClientAuthType clientAuth; // If we are a client should we request a client certificate
  final List<Certificate> localCertificates;
  final Map<String, Certificate> nameToCertificate;
  final bool insecureSkipVerify;
  final bool insecureVerification;
  final VerifyPeerCertificateFn? verifyPeerCertificate;
  final ServerCertVerifier serverCertVerifier;
  final ClientCertVerifier? clientCertVerifier;
  final Duration retransmitInterval;
  final int initialEpoch;

  HandshakeConfig({
    this.localPskCallback,
    this.localPskIdentityHint,
    this.localCipherSuites = const [],
    this.localSignatureSchemes = const [],
    this.extendedMasterSecret = ExtendedMasterSecretType.Disable,
    this.localSrtpProtectionProfiles = const [],
    this.serverName = '',
    this.clientAuth = ClientAuthType.NoClientCert,
    this.localCertificates = const [],
    this.nameToCertificate = const {},
    this.insecureSkipVerify = false,
    this.insecureVerification = false,
    this.verifyPeerCertificate,
    required this.serverCertVerifier,
    this.clientCertVerifier,
    this.retransmitInterval = Duration.zero,
    this.initialEpoch = 0,
  });

  Future<Certificate> getCertificate(String serverName) async {
    if (localCertificates.isEmpty) {
      throw Error('ErrNoCertificates');
    }

    if (localCertificates.length == 1) {
      return localCertificates[0];
    }

    if (serverName.isEmpty) {
      return localCertificates[0];
    }

    String lower = serverName.toLowerCase();
    String name = lower.endsWith('.') ? lower.substring(0, lower.length - 1) : lower;

    if (nameToCertificate.containsKey(name)) {
      return nameToCertificate[name]!;
    }

    List<String> labels = name.split('.');
    for (int i = 0; i < labels.length; i++) {
      labels[i] = "*";
      String candidate = labels.join(".");
      if (nameToCertificate.containsKey(candidate)) {
        return nameToCertificate[candidate]!;
      }
    }

    return localCertificates[0];
  }

  static Future<rustls.RootCertStore> genSelfSignedRootCert() async {
    var certs = rustls.RootCertStore.empty();
    certs.add(await rcgen.generateSimpleSelfSigned([]));
    return certs;
  }

  static HandshakeConfig defaultConfig() {
    return HandshakeConfig(
      serverCertVerifier: rustls.client.WebPkiServerVerifier.builder(
        Arc(genSelfSignedRootCert())
      ).build(),
    );
  }
}

class DTLSConn {
  Future<void> handshake(HandshakeState state) async {
    while (true) {
      trace(
        '[handshake:${srvCliStr(state)}] ${currentFlight.toString()}: ${state.toString()}',
      );

      if (state == HandshakeState.Finished && !isHandshakeCompletedSuccessfully()) {
        setHandshakeCompletedSuccessfully();
        handshakeDoneTx.take();
        return;
      }

      state = await _nextState(state);
    }
  }

  Future<HandshakeState> _nextState(HandshakeState state) async {
    switch (state) {
      case HandshakeState.Preparing:
        return await prepare();
      case HandshakeState.Sending:
        return await send();
      case HandshakeState.Waiting:
        return await wait();
      case HandshakeState.Finished:
        return await finish();
      default:
        throw Error('ErrInvalidFsmTransition');
    }
  }

  Future<HandshakeState> prepare() async {
    flights = null;
    retransmit = currentFlight.hasRetransmit();

    var result = await currentFlight.generate(state, cache, cfg);

    if (result is Error) {
      // handle error here
    }

    if (result is List) {
      flights = result;
    }

    int epoch = cfg.initialEpoch;
    int nextEpoch = epoch;

    for (var p in flights!) {
      p.record.recordLayerHeader.epoch += epoch;
      if (p.record.recordLayerHeader.epoch > nextEpoch) {
        nextEpoch = p.record.recordLayerHeader.epoch;
      }
      if (p.record.content is Content.Handshake) {
        (p.record.content as Content.Handshake).handshakeHeader.messageSequence = state.handshakeSendSequence as int;
        state.handshakeSendSequence++;
      }
    }

    if (epoch != nextEpoch) {
      trace('[handshake:${srvCliStr(state)}] -> changeCipherSpec (epoch: $nextEpoch)');
      setLocalEpoch(nextEpoch);
    }

    return HandshakeState.Sending;
  }

  Future<HandshakeState> send() async {
    if (flights != null) {
      await writePackets(flights!);
    }

    if (currentFlight.isLastSendFlight()) {
      return HandshakeState.Finished;
    } else {
      return HandshakeState.Waiting;
    }
  }

  Future<HandshakeState> wait() async {
    var retransmitTimer = Future.delayed(cfg.retransmitInterval);

    var doneSenders = await handshakeRx.recv();
    if (doneSenders == null) {
      trace('[handshake:${srvCliStr(state)}] ${currentFlight.toString()} handshakeTx is dropped');
      return Error('ErrAlertFatalOrClose');
    }

    var result = await currentFlight.parse(handleQueueTx, state, cache, cfg);
    return result is Error ? Error(result.toString()) : HandshakeState.Preparing;
  }

  Future<HandshakeState> finish() async {
    var retransmitTimer = Future.delayed(cfg.retransmitInterval);

    var done = await handshakeRx.recv();
    if (done == null) {
      trace('[handshake:${srvCliStr(state)}] ${currentFlight.toString()} handshakeTx is dropped');
      return Error('ErrAlertFatalOrClose');
    }

    var result = await currentFlight.parse(handleQueueTx, state, cache, cfg);
    return result is Error ? Error(result.toString()) : HandshakeState.Finished;
  }

  String srvCliStr(HandshakeState state) {
    return state == HandshakeState.Finished ? 'client' : 'server';
  }

  Future<void> writePackets(List pkts) async {
    // Implementation here
  }

  void trace(String message) {
    //print(message);
  }

  bool isHandshakeCompletedSuccessfully() {
    return true;
  }

  void setHandshakeCompletedSuccessfully() {
    // Implementation here
  }

  void setLocalEpoch(int epoch) {
    // Implementation here
  }

  late HandshakeState currentFlight;
  late Future handshakeRx;
  late Future handshakeDoneTx;
  late Future handleQueueTx;
  late Future cache;
  late Future cfg;
  List? flights;
  bool retransmit = false;
}

void main() {
  // Example usage
}
