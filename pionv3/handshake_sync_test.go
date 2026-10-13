// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop && go1.25

package pionv3

import (
	"context"
	"crypto/rand"
	"io"
	"net"

	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

func TestPionV3ReadUnblocksOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, cb.Close())
		}()

		readErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			_, rErr := ca.Read(buf)
			readErr <- rErr
		}()

		assert.NoError(t, ca.Close())
		assert.NoError(t, ca.Close())

		err = <-readErr
		assertInteropError(t, err, io.EOF)
	})
}

func TestPionV3PSKMismatchNoRetransmitLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		var serverWrites atomic.Int32
		var clientWrites atomic.Int32

		ca, cb := packetPipe()
		defer func() {
			_ = ca.Close()
		}()
		defer func() {
			_ = cb.Close()
		}()

		caCount := &connWithCallback{packetTestConn: ca}
		caCount.onWrite = func([]byte) {
			clientWrites.Add(1)
		}
		cbCount := &connWithCallback{packetTestConn: cb}
		cbCount.onWrite = func([]byte) {
			serverWrites.Add(1)
		}

		clientErr := make(chan error, 1)
		serverErr := make(chan error, 1)

		go func() {
			opts := []dtls.ClientOption{dtls.WithPSKIdentityHint([]byte("Client Identity")), withPSK(func() ([]psk, error) {
				return []psk{{Identity: []byte("Client Identity"), Key: []byte("client-psk")}}, nil
			}, nil), dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8)}

			c, err := testClient(ctx, caCount, caCount.RemoteAddr(), opts, false)
			if c != nil {
				_ = c.Close()
			}
			clientErr <- err
		}()

		go func() {
			opts := []dtls.ServerOption{withPSK(nil, func(identities [][]byte) (*psk, error) {
				return &psk{Identity: identities[0], Key: []byte("server-psk")}, nil
			}), dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8)}

			s, err := testServer(ctx, cbCount, cbCount.RemoteAddr(), opts, false)
			if s != nil {
				_ = s.Close()
			}
			serverErr <- err
		}()

		serverErrRes := <-serverErr
		clientErrRes := <-clientErr

		assert.ErrorIs(t, serverErrRes, context.DeadlineExceeded)
		assert.ErrorIs(t, clientErrRes, context.DeadlineExceeded)

		serverCount := serverWrites.Load()
		clientCount := clientWrites.Load()

		time.Sleep(2 * time.Second)
		synctest.Wait()

		assert.Equal(t, serverCount, serverWrites.Load(), "Server should not retransmit after handshake failure")
		assert.Equal(t, clientCount, clientWrites.Load(), "Client should not retransmit after handshake failure")
		assert.LessOrEqual(t, serverCount, int32(20), "Server retransmit count too high for backoff")
		assert.LessOrEqual(t, clientCount, int32(20), "Client retransmit count too high for backoff")
	})
}

func TestPionV3PSKServerKeyExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var gotServerKeyExchange atomic.Bool

		clientErr := make(chan error, 1)
		serverHandshakeDone := make(chan struct{})
		ca, cb := packetPipe()
		cbAnalyzer := &connWithCallback{packetTestConn: cb}
		cbAnalyzer.onWrite = func(in []byte) {
			messages, err := recordlayer.UnpackDatagram(
				in)
			assert.NoError(t, err)

			for i := range messages {
				header, err := parseRecord(messages[i], 0)
				if err != nil {
					continue
				}
				if header.ContentType != protocol.ContentTypeHandshake || header.Epoch != 0 {
					continue
				}
				payload := messages[i][recordlayer.FixedHeaderSize:]
				for len(payload) >= handshake.HeaderLength {
					var h handshake.Header
					if err := h.Unmarshal(payload); err != nil {
						break
					}
					if h.Type == handshake.TypeServerKeyExchange {
						gotServerKeyExchange.Store(true)

						break
					}
					fragLen := int(h.FragmentLength)
					if fragLen <= 0 || handshake.HeaderLength+fragLen > len(payload) {
						break
					}
					payload = payload[handshake.HeaderLength+fragLen:]
				}
			}
		}

		go func() {
			opts := []dtls.ClientOption{dtls.WithPSKIdentityHint([]byte{0xAB, 0xC1, 0x23}), withPSK(func() ([]psk, error) {
				return []psk{{Identity: []byte{0xAB, 0xC1, 0x23}, Key: []byte{0xAB, 0xC1, 0x23}}}, nil
			}, nil), dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8)}

			if client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false); err != nil {
				clientErr <- err
			} else {
				<-serverHandshakeDone
				clientErr <- client.Close()
			}
		}()

		opts := []dtls.ServerOption{withPSK(nil, func(identities [][]byte) (*psk, error) {
			return &psk{Identity: identities[0], Key: []byte{0xAB, 0xC1, 0x23}}, nil
		}), dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8)}

		server, err := testServer(ctx, cbAnalyzer, cbAnalyzer.RemoteAddr(), opts, false)
		close(serverHandshakeDone)
		assert.NoError(t, err)

		receivedServerKeyExchange := gotServerKeyExchange.Load()

		assert.NoError(t, server.Close())
		if err := <-clientErr; err != nil {
			assertInteropError(
				t,
				err,
				expectedTextError("alert: "+(&alert.Alert{
					Level:       alert.Warning,
					Description: alert.CloseNotify,
				}).String()),
				"TestPSK: Client error",
			)
		}
		assert.False(t, receivedServerKeyExchange)
	})
}

func TestPionV3ClientTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		clientErr := make(chan error, 1)

		ca, _ := packetPipe()
		go func() {
			c, err := testClient(ctx, ca, ca.RemoteAddr(), nil, true)
			if err == nil {
				_ = c.Close()
			}
			clientErr <- err
		}()

		err := <-clientErr
		var netErr net.Error
		assert.ErrorAs(t, err, &netErr, "Client error exp(Temporary network error) failed")
		assert.True(t, netErr.Timeout(), "Client error exp(Timeout) failed")
	})
}

func TestPionV3ServerTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cookie := make([]byte, 20)
		_, err := rand.Read(cookie)
		assert.NoError(t, err)

		var rand [28]byte
		random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

		cipherSuites := []uint16{
			uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			uint16(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		}

		extensions := []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.RSA},
					{Hash: hash.SHA512, Signature: signature.RSA},
				},
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}

		record := &testRecord{
			Header: recordlayer.Header{
				SequenceNumber: 0,
				Version:        protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{
					MessageSequence: 0,
				},
				Message: &handshake.MessageClientHello{
					Version:            protocol.Version1_2,
					Cookie:             cookie,
					Random:             random,
					CipherSuiteIDs:     cipherSuites,
					CompressionMethods: []*protocol.CompressionMethod{protocol.CompressionMethods()[0]},
					Extensions:         extensions,
				},
			},
		}

		packet, err := record.Marshal()
		assert.NoError(t, err)

		ca, cb := packetPipe()
		defer func() {
			assert.NoError(t, ca.Close())
		}()

		caReadChan := make(chan []byte, 1000)
		go func() {
			for {
				data := make([]byte, 8192)
				n, err := ca.Read(data)
				if err != nil {
					return
				}

				caReadChan <- data[:n]
			}
		}()

		go func() {
			for {
				select {
				case <-time.After(10 * time.Millisecond):
					_, err := ca.Write(packet)
					if err != nil {
						return
					}
				case <-caReadChan:

					return
				}
			}
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()

		serverOpts := []dtls.ServerOption{
			dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			dtls.WithFlightInterval(100 * time.Millisecond),
		}

		_, serverErr := testServer(ctx, cb, cb.RemoteAddr(), serverOpts, true)
		var netErr net.Error
		assert.ErrorAsf(t, serverErr, &netErr, "Client error exp(Temporary network error) failed(%v)", serverErr)
		assert.Truef(t, netErr.Timeout(), "Client error exp(Temporary network error) failed(%v)", serverErr)

		time.Sleep(300 * time.Millisecond)
		synctest.Wait()

		select {
		case msg := <-caReadChan:
			assert.Fail(t, "Expected no additional messages from server", "got: %+v", msg)
		default:
		}
	})
}

func TestPionV3RenegotiationInfo(t *testing.T) {
	resp := make([]byte, 1024)

	for _, testCase := range []struct {
		Name                     string
		ExpectRenegotiationInfo  bool
		SendRenegotiationInfoExt bool
		IncludeRenegotiationSCSV bool
	}{
		{
			Name:                     "Include RenegotiationInfo",
			ExpectRenegotiationInfo:  true,
			SendRenegotiationInfoExt: true,
		},
		{
			Name:                     "RenegotiationInfo SCSV",
			ExpectRenegotiationInfo:  true,
			IncludeRenegotiationSCSV: true,
		},
		{
			Name:                    "No RenegotiationInfo",
			ExpectRenegotiationInfo: false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ca, cb := packetPipe()
				defer func() {
					assert.NoError(t, ca.Close())
				}()

				ctx := t.Context()

				go func() {
					_, err := testServer(
						ctx,
						cb,
						cb.RemoteAddr(),
						nil,
						true,
					)
					assertInteropError(t, err, context.Canceled)
				}()

				time.Sleep(50 * time.Millisecond)
				synctest.Wait()

				extensions := []extension.Extension{}
				if test.SendRenegotiationInfoExt {
					extensions = append(extensions, &extension.RenegotiationInfo{
						RenegotiatedConnection: 0,
					})
				}
				cipherSuites := []uint16{
					uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					uint16(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
				}
				if test.IncludeRenegotiationSCSV {
					cipherSuites = append(cipherSuites, renegotiationInfoSCSV)
				}
				err := sendClientHello([]byte{}, ca, 0, extensions, cipherSuites...)
				assert.NoError(t, err)

				n, err := ca.Read(resp)
				assert.NoError(t, err)

				_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])
				helloVerifyRequest, ok := handshakeRecord.Message.(*handshake.MessageHelloVerifyRequest)
				assert.True(t, ok)

				err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions, cipherSuites...)
				assert.NoError(t, err)

				n, err = ca.Read(resp)
				assert.NoError(t, err)

				messages, err := recordlayer.UnpackDatagram(
					resp[:n])
				assert.NoError(t, err)
				_, handshakeRecord = unmarshalHandshakeRecord(t, messages[0])

				serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
				assert.True(t, ok)

				actualNegotationInfo := false
				for _, v := range serverHello.Extensions {
					if _, ok := v.(*extension.RenegotiationInfo); ok {
						actualNegotationInfo = true
					}
				}
				assert.True(
					t,
					test.ExpectRenegotiationInfo == actualNegotationInfo,
					"NegotationInfo state in ServerHello is incorrect: expected(%t) actual(%t)",
					test.ExpectRenegotiationInfo,
					actualNegotationInfo,
				)
			})
		})
	}
}

func TestPionV3ALPNExtension(t *testing.T) {
	for _, test := range []struct {
		Name                   string
		ClientProtocolNameList []string
		ServerProtocolNameList []string
		ExpectedProtocol       string
		ExpectAlertFromClient  bool
		ExpectAlertFromServer  bool
		Alert                  alert.Description
	}{
		{
			Name:                   "Negotiate a protocol",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{"spd/1"},
			ExpectedProtocol:       "spd/1",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Server doesn't support any",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Negotiate with higher server precedence",
			ClientProtocolNameList: []string{"http/1.1", "spd/1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "http/3", "spd/1"},
			ExpectedProtocol:       "http/3",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Empty intersection",
			ClientProtocolNameList: []string{"http/1.1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "spd/1"},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  true,
			Alert:                  alert.NoApplicationProtocol,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()

				ca, cb := packetPipe()
				go func() {
					var opts []dtls.ClientOption
					if len(test.ClientProtocolNameList) > 0 {
						opts = append(opts, dtls.WithSupportedProtocols(test.ClientProtocolNameList...))
					}
					_, _ = testClient(ctx, ca, ca.RemoteAddr(), opts, false)
				}()

				resp := make([]byte, 1024)
				n, err := cb.Read(resp)
				assert.NoError(t, err)

				ctx2, cancel2 := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel2()

				ca2, cb2 := packetPipe()
				go func() {
					var opts []dtls.ServerOption
					if len(test.ServerProtocolNameList) > 0 {
						opts = append(opts, dtls.WithSupportedProtocols(test.ServerProtocolNameList...))
					}
					_, err2 := testServer(ctx2, cb2, cb2.RemoteAddr(), opts, true)
					if test.ExpectAlertFromServer {
						assert.NotErrorIs(t, err2, context.Canceled)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				_, err = ca2.Write(resp[:n])
				assert.NoError(t, err)

				resp2 := make([]byte, 1024)
				n, err = ca2.Read(resp2)
				assert.NoError(t, err)

				_, err = cb.Write(resp2[:n])
				assert.NoError(t, err)

				resp3 := make([]byte, 1024)
				n, err = cb.Read(resp3)
				assert.NoError(t, err)

				_, err = ca2.Write(resp3[:n])
				assert.NoError(t, err)

				resp4 := make([]byte, 1024)
				n, err = ca2.Read(resp4)
				assert.NoError(t, err)

				messages, err := recordlayer.UnpackDatagram(
					resp4[:n])
				assert.NoError(t, err)

				if test.ExpectAlertFromServer {
					a := unmarshalAlertRecord(t, messages[0])
					assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
				} else {
					recordHeader, handshakeRecord := unmarshalHandshakeRecord(t, messages[0])
					serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
					assert.True(t, ok)

					var negotiatedProtocol string
					for i, v := range serverHello.Extensions {
						if _, ok := v.(*extension.ALPN); ok {
							e, ok := v.(*extension.ALPN)
							assert.True(t, ok)

							negotiatedProtocol = e.ProtocolNameList[0]

							if test.ExpectAlertFromClient {
								serverHello.Extensions[i] = &extension.ALPN{ProtocolNameList: []string{"h2", "oops"}}
							}
						}
					}

					assert.Equalf(t, test.ExpectedProtocol, negotiatedProtocol, "ALPN %v", test.Name)

					s, err := marshalTestRecord(
						recordlayer.Header{
							Version:        recordHeader.Version,
							Epoch:          recordHeader.Epoch,
							SequenceNumber: recordHeader.SequenceNumber,
							ConnectionID:   recordHeader.ConnectionID,
						},
						handshakeRecord,
					)
					assert.NoError(t, err)

					_, err = cb.Write(s)
					assert.NoError(t, err)

					if test.ExpectAlertFromClient {
						resp5 := make([]byte, 1024)
						n, err = cb.Read(resp5)
						assert.NoError(t, err)

						a := unmarshalAlertRecord(t, resp5[:n])
						assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
					}
				}

				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
			})
		})
	}
}

func TestPionV3SupportedGroupsExtension(t *testing.T) {
	t.Run("ServerHello Supported Groups", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			go func() {
				_, err := testServer(ctx, cb, cb.RemoteAddr(), nil, true)
				assertInteropError(t, err, context.Canceled)
			}()
			extensions := []extension.Extension{
				&extension.SupportedEllipticCurves{EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384}},
				&extension.SupportedPointFormats{
					PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
				},
			}

			time.Sleep(50 * time.Millisecond)

			resp := make([]byte, 1024)
			err := sendClientHello([]byte{}, ca, 0, extensions)
			assert.NoError(t, err)

			n, err := ca.Read(resp)
			assert.NoError(t, err)

			_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])

			helloVerifyRequest, ok := handshakeRecord.Message.(*handshake.MessageHelloVerifyRequest)
			assert.True(t, ok, "Failed to cast MessageHelloVerifyRequest")

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
			assert.NoError(t, err)

			n, err = ca.Read(resp)
			assert.NoError(t, err)

			messages, err := recordlayer.UnpackDatagram(
				resp[:n])
			assert.NoError(t, err)
			_, handshakeRecord = unmarshalHandshakeRecord(t, messages[0])

			serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
			assert.True(t, ok, "TestSupportedGroups: Failed to cast MessageServerHello")

			gotGroups := false
			for _, v := range serverHello.Extensions {
				if _, ok := v.(*extension.SupportedEllipticCurves); ok {
					gotGroups = true
				}
			}

			assert.False(t, gotGroups, "TestSupportedGroups: supported_groups extension was sent in ServerHello")
		})
	})
}
