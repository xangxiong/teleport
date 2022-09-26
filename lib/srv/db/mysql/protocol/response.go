/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

// import "github.com/gravitational/trace"

// // OK represents the OK packet.
// //
// // https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
// // https://mariadb.com/kb/en/ok_packet/
// type OK struct {
// 	packet
// }

// // Error represents the ERR packet.
// //
// // https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
// // https://mariadb.com/kb/en/err_packet/
// type Error struct {
// 	packet

// 	// message is the error message
// 	message string
// }

// // Error returns the error message.
// func (p *Error) Error() string {
// 	return p.message
// }

// // parseOKPacket parses packet bytes and returns a Packet if successful.
// func parseOKPacket(packetBytes []byte) (Packet, error) {
// 	return &OK{
// 		packet: packet{bytes: packetBytes},
// 	}, nil
// }

// // parseErrorPacket parses packet bytes and returns a Packet if successful.
// func parseErrorPacket(packetBytes []byte) (Packet, error) {
// 	// Figure out where in the packet the error message is.
// 	//
// 	// Depending on the protocol version, the packet may include additional
// 	// fields. In protocol version 4.1 it includes '#' marker:
// 	//
// 	// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
// 	minLen := packetHeaderSize + packetTypeSize + 2 // 4-byte header + 1-byte type + 2-byte error code
// 	if len(packetBytes) > minLen && packetBytes[minLen] == '#' {
// 		minLen += 6 // 1-byte marker '#' + 5-byte state
// 	}

// 	// Be a bit paranoid and make sure the packet is not truncated.
// 	if len(packetBytes) < minLen {
// 		return nil, trace.BadParameter("failed to parse ERR packet: %v", packetBytes)
// 	}

// 	return &Error{
// 		packet:  packet{bytes: packetBytes},
// 		message: string(packetBytes[minLen:]),
// 	}, nil
// }
