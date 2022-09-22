/*
Copyright 2021 Gravitational, Inc.

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

import (
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"

	"github.com/gravitational/trace"
)

// MessageOpUpdate represents parsed OP_UPDATE wire message.
//
// https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#op_update
//
//	struct OP_UPDATE {
//	    MsgHeader header;             // standard message header
//	    int32     ZERO;               // 0 - reserved for future use
//	    cstring   fullCollectionName; // "dbname.collectionname"
//	    int32     flags;              // bit vector. see below
//	    document  selector;           // the query to select the document
//	    document  update;             // specification of the update to perform
//	}
//
// OP_UPDATE is deprecated starting MongoDB 5.0 in favor of OP_MSG.
type MessageOpUpdate struct {
	Header             MessageHeader
	Zero               int32
	FullCollectionName string
	Flags              int32
	Selector           bsoncore.Document
	Update             bsoncore.Document
	// bytes is the full wire message bytes (incl. header) read from the connection.
	bytes []byte
}

// GetHeader returns the wire message header.
func (m *MessageOpUpdate) GetHeader() MessageHeader {
	return m.Header
}

// GetBytes returns the message raw bytes read from the connection.
func (m *MessageOpUpdate) GetBytes() []byte {
	return m.bytes
}

// GetDatabase returns the command's database.
func (m *MessageOpUpdate) GetDatabase() (string, error) {
	// Full collection name has "<db>.<collection>" format.
	return strings.Split(m.FullCollectionName, ".")[0], nil
}

// GetCommand returns the message's command.
func (m *MessageOpUpdate) GetCommand() (string, error) {
	return "update", nil
}

// String returns the message string representation.
func (m *MessageOpUpdate) String() string {
	return fmt.Sprintf("OpUpdate(FullCollectionName=%v, Selector=%v, Update=%v, Flags=%v)",
		m.FullCollectionName, m.Selector.String(), m.Update.String(), m.Flags)
}

// MoreToCome is whether sender will send another message right after this one.
func (m *MessageOpUpdate) MoreToCome(_ Message) bool {
	return true
}

// readOpUpdate converts OP_UPDATE wire message bytes to a structured form.
func readOpUpdate(header MessageHeader, payload []byte) (*MessageOpUpdate, error) {
	zero, rem, ok := readInt32(payload)
	if !ok {
		return nil, trace.BadParameter("malformed OP_UPDATE: missing zero %v", payload)
	}
	fullCollectionName, rem, ok := readCString(rem)
	if !ok {
		return nil, trace.BadParameter("malformed OP_UPDATE: missing full collection name %v", payload)
	}
	flags, rem, ok := readInt32(rem)
	if !ok {
		return nil, trace.BadParameter("malformed OP_UPDATE: missing flags %v", payload)
	}
	selector, rem, ok := bsoncore.ReadDocument(rem)
	if !ok {
		return nil, trace.BadParameter("malformed OP_UPDATE: missing selector %v", payload)
	}
	update, _, ok := bsoncore.ReadDocument(rem)
	if !ok {
		return nil, trace.BadParameter("malformed OP_UPDATE: missing update %v", payload)
	}
	return &MessageOpUpdate{
		Header:             header,
		Zero:               zero,
		FullCollectionName: fullCollectionName,
		Flags:              flags,
		Selector:           selector,
		Update:             update,
		bytes:              append(header.bytes[:], payload...),
	}, nil
}

// ToWire converts this message to wire protocol message bytes.
func (m *MessageOpUpdate) ToWire(responseTo int32) (dst []byte) {
	var idx int32
	idx, dst = wiremessage.AppendHeaderStart(dst, m.Header.RequestID, responseTo, wiremessage.OpUpdate)
	dst = appendInt32(dst, m.Zero)
	dst = appendCString(dst, m.FullCollectionName)
	dst = appendInt32(dst, m.Flags)
	dst = bsoncore.AppendDocument(dst, m.Selector)
	dst = bsoncore.AppendDocument(dst, m.Update)
	return bsoncore.UpdateLength(dst, idx, int32(len(dst[idx:])))
}
