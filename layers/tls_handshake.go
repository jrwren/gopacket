// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/google/gopacket"
)

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	Type    TLSHandshakeType
	Payload []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	t.Type = TLSHandshakeType(data[0])
	t.Payload = data
	return nil
}

type TLSHandshakeType uint8

// TLS handshake message types.
const (
	TLSHandshakeClientHello        TLSHandshakeType = 1
	TLSHandshakeServerHello        TLSHandshakeType = 2
	TLSHandshakeNewSessionTicket   TLSHandshakeType = 4
	TLSHandshakeCertificate        TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange  TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerHelloDone    TLSHandshakeType = 14
	TLSHandshakeCertificateVerify  TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange  TLSHandshakeType = 16
	TLSHandshakeFinished           TLSHandshakeType = 20
	TLSHandshakeCertificateStatus  TLSHandshakeType = 22
	TLSHandshakeNextProtocol       TLSHandshakeType = 67 // Not IANA assigned
)
