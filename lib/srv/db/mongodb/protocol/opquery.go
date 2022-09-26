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

// import (
// 	"fmt"
// 	"strings"

// 	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
// 	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"

// 	"github.com/gravitational/trace"
// )

// // MessageOpQuery represents parsed OP_QUERY wire message.
// //
// // https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#op_query
// //
// // OP_QUERY is generally deprecated by MongoDB in favor of extensible OP_MSG
// // message but it still seems to be used by Mongo clients and drivers during
// // initial connection establishment.
// type MessageOpQuery struct {
// 	Header               MessageHeader
// 	Flags                wiremessage.QueryFlag
// 	FullCollectionName   string
// 	NumberToSkip         int32
// 	NumberToReturn       int32
// 	Query                bsoncore.Document
// 	ReturnFieldsSelector bsoncore.Document
// 	// bytes is the full wire message bytes (incl. header) read from the connection.
// 	bytes []byte
// }

// // GetHeader returns the wire message header.
// func (m *MessageOpQuery) GetHeader() MessageHeader {
// 	return m.Header
// }

// // GetBytes returns the message raw bytes read from the connection.
// func (m *MessageOpQuery) GetBytes() []byte {
// 	return m.bytes
// }

// // GetDatabase returns the command's database.
// func (m *MessageOpQuery) GetDatabase() (string, error) {
// 	// Full collection name has "<db>.<collection>" format.
// 	return strings.Split(m.FullCollectionName, ".")[0], nil
// }

// // GetCommand returns the message's command.
// func (m *MessageOpQuery) GetCommand() (string, error) {
// 	// Command is the first element of the query document e.g.
// 	// { "authenticate": 1, "mechanism": ... }
// 	cmd, err := m.Query.IndexErr(0)
// 	if err != nil {
// 		return "", trace.Wrap(err)
// 	}
// 	return cmd.Key(), nil
// }

// // String returns the message string representation.
// func (m *MessageOpQuery) String() string {
// 	return fmt.Sprintf("OpQuery(FullCollectionName=%v, Query=%v, ReturnFieldsSelector=%v, NumberToSkip=%v, NumberToReturn=%v, Flags=%v)",
// 		m.FullCollectionName, m.Query.String(), m.ReturnFieldsSelector.String(), m.NumberToSkip, m.NumberToReturn, m.Flags.String())
// }

// // MoreToCome is whether sender will send another message right after this one.
// func (m *MessageOpQuery) MoreToCome(_ Message) bool {
// 	return false
// }

// // readOpQuery converts OP_QUERY wire message bytes to a structured form.
// //
// // https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#op_query
// func readOpQuery(header MessageHeader, payload []byte) (*MessageOpQuery, error) {
// 	flags, rem, ok := wiremessage.ReadQueryFlags(payload)
// 	if !ok {
// 		return nil, trace.BadParameter("malformed OP_QUERY: missing flags %v", payload)
// 	}
// 	fullCollectionName, rem, ok := wiremessage.ReadQueryFullCollectionName(rem)
// 	if !ok {
// 		return nil, trace.BadParameter("malformed OP_QUERY: missing full collection name %v", payload)
// 	}
// 	numberToSkip, rem, ok := wiremessage.ReadQueryNumberToSkip(rem)
// 	if !ok {
// 		return nil, trace.BadParameter("malformed OP_QUERY: missing number to skip %v", payload)
// 	}
// 	numberToReturn, rem, ok := wiremessage.ReadQueryNumberToReturn(rem)
// 	if !ok {
// 		return nil, trace.BadParameter("malformed OP_QUERY: missing number to return %v", payload)
// 	}
// 	query, rem, ok := wiremessage.ReadQueryQuery(rem)
// 	if !ok {
// 		return nil, trace.BadParameter("malformed OP_QUERY: missing query %v", payload)
// 	}
// 	var returnFieldsSelector bsoncore.Document
// 	if len(rem) > 0 {
// 		returnFieldsSelector, _, ok = wiremessage.ReadQueryReturnFieldsSelector(rem)
// 		if !ok {
// 			return nil, trace.BadParameter("malformed OP_QUERY: missing return field selector %v", payload)
// 		}
// 	}
// 	return &MessageOpQuery{
// 		Header:               header,
// 		Flags:                flags,
// 		FullCollectionName:   fullCollectionName,
// 		NumberToSkip:         numberToSkip,
// 		NumberToReturn:       numberToReturn,
// 		Query:                query,
// 		ReturnFieldsSelector: returnFieldsSelector,
// 		bytes:                append(header.bytes[:], payload...),
// 	}, nil
// }

// // ToWire converts this message to wire protocol message bytes.
// //
// // https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#op_query
// func (m *MessageOpQuery) ToWire(responseTo int32) (dst []byte) {
// 	var idx int32
// 	idx, dst = wiremessage.AppendHeaderStart(dst, m.Header.RequestID, responseTo, wiremessage.OpQuery)
// 	dst = wiremessage.AppendQueryFlags(dst, m.Flags)
// 	dst = wiremessage.AppendQueryFullCollectionName(dst, m.FullCollectionName)
// 	dst = wiremessage.AppendQueryNumberToSkip(dst, m.NumberToSkip)
// 	dst = wiremessage.AppendQueryNumberToReturn(dst, m.NumberToReturn)
// 	dst = bsoncore.AppendDocument(dst, m.Query)
// 	if len(m.ReturnFieldsSelector) > 0 {
// 		dst = bsoncore.AppendDocument(dst, m.ReturnFieldsSelector)
// 	}
// 	return bsoncore.UpdateLength(dst, idx, int32(len(dst[idx:])))
// }
