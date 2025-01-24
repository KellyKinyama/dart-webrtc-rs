import 'dart:typed_data';

Uint8List intToUint8SeqNum(int sequenceNumber) {
  ByteData writer = ByteData.sublistView(Uint8List(6));
  writer.setUint8(0, (sequenceNumber >> 40) & 0xFF);
  writer.setUint8(1, (sequenceNumber >> 32) & 0xFF);
  writer.setUint8(2, (sequenceNumber >> 24) & 0xFF);
  writer.setUint8(3, (sequenceNumber >> 16) & 0xFF);
  writer.setUint8(4, (sequenceNumber >> 8) & 0xFF);
  writer.setUint8(5, sequenceNumber & 0xFF);
  return writer.buffer.asUint8List();
}
