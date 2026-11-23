//! Core protocol flows over the public API: handshake establishment,
//! bidirectional transport, padding, PSKs, buffers, stats.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use common::{Opts, Polled, Rx, Tx, a_addr, b_addr, new_pair, new_pair_opts, new_pair_with};
use wireguard_sans_io::{
    DropReason, Encapsulated, Error, PacketKind, PollOutput, SendReason, consts, ip_packet_len,
    peek, transport_datagram_len,
};

#[test]
fn full_handshake_and_bidirectional_transport() {
    let mut p = new_pair(1);
    assert_eq!(p.establish(), 4);
    // A → B and B → A, various sizes incl. boundary cases.
    for len in [1usize, 15, 16, 17, 64, 255, 1024, 1420] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        p.assert_roundtrip_a_to_b(&payload);
        let wire = p.seal_from_b(&payload);
        let got = p.open_at_a(&wire);
        assert_eq!(&got[..len], payload.as_slice());
    }
    let stats = p.a.tunnel.stats();
    assert_eq!(stats.handshakes_completed, 1);
    assert!(stats.tx_transport > 8);
    assert_eq!(stats.auth_failures, 0);
    assert_eq!(p.b.tunnel.stats().handshakes_completed, 1);
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 1);
}

#[test]
fn handshake_wire_messages_have_spec_sizes() {
    let mut p = new_pair(2);
    let now = p.clock.now();
    // Data with no session: nothing is consumed, and the handshake comes
    // out of poll().
    assert_eq!(p.a.send(now, b"data"), Tx::NoSession);
    let init = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, dst) => {
            assert_eq!(dst, b_addr(), "initiation goes to the configured endpoint");
            w
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(init.len(), consts::HANDSHAKE_INITIATION_LEN);
    assert_eq!(init[0], 1);
    assert_eq!(&init[1..4], &[0, 0, 0]);

    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(resp.len(), consts::HANDSHAKE_RESPONSE_LEN);
    assert_eq!(resp[0], 2);

    // Keepalive datagram is exactly 32 bytes; data is padded to 16.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let ka = match p.a.send(now, b"") {
        Tx::Transport(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(ka.len(), consts::KEEPALIVE_LEN);
    let one = match p.a.send(now, b"x") {
        Tx::Transport(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(one.len(), 16 + 16 + 16); // header + padded(1)=16 + tag
    assert_eq!(one.len(), transport_datagram_len(1));
}

#[test]
fn payload_not_consumed_until_established() {
    let mut p = new_pair(3);
    let now = p.clock.now();
    // Every send before the handshake completes reports NoSession; none
    // of them writes or sends anything by itself.
    assert_eq!(p.a.send(now, b"hello"), Tx::NoSession);
    assert_eq!(p.a.send(now, b"hello"), Tx::NoSession);
    assert!(!p.a.is_established(now));
    // Exactly one initiation comes out of poll, however many sends asked.
    let (wires, events) = p.a.drain(now, &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    assert!(events.is_empty());
    assert_eq!(p.a.send(now, b"hello"), Tx::NoSession);
    assert_eq!(p.a.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 1);
    assert_eq!(p.a.tunnel.stats().tx_transport, 0);
}

#[test]
fn no_endpoint_means_nothing_can_be_sent_until_the_peer_calls() {
    // B is a pure responder: it does not know where A is.
    let mut p = new_pair_opts(
        30,
        Opts {
            b_without_endpoint: true,
            ..Opts::default()
        },
    );
    let now = p.clock.now();
    assert_eq!(p.b.tunnel.endpoint(), None);
    assert_eq!(p.b.send(now, b"hello"), Tx::NoEndpoint);
    // Nothing to do: no initiation can be addressed anywhere.
    assert_eq!(p.b.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(
        p.b.tunnel.next_wake(),
        None,
        "no busy wake-up without an endpoint"
    );

    // A initiates; B learns A's address from the authenticated handshake
    // and the response is addressed to it.
    let init = p.a_initiates();
    let info = p.deliver_to_b(&init);
    assert!(matches!(info.rx, Rx::Response(_)));
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}

#[test]
fn responder_cannot_send_before_confirmation() {
    let mut p = new_pair(4);
    let now = p.clock.now();
    let init = p.a_initiates();
    let info = p.deliver_to_b(&init);
    let resp = match info.rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert!(
        !info.session_established,
        "an unconfirmed responder session is not established"
    );
    // B (responder) has an unconfirmed session: whitepaper §5.1 forbids
    // sending transport data on it.
    assert!(!p.b.is_established(now));
    assert_eq!(p.b.send(now, b"reply"), Tx::NoSession);
    // A completes; A's first data confirms B's session.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let data = p.seal_from_a(b"ping");
    let info = p.deliver_to_b(&data);
    assert!(matches!(info.rx, Rx::Data(_)));
    assert!(
        info.session_established,
        "the confirming packet reports the session to the responder"
    );
    assert!(p.b.is_established(now));
    // Now B can answer over the tunnel.
    let reply = p.seal_from_b(b"pong");
    assert_eq!(&p.open_at_a(&reply)[..4], b"pong");
    // A second packet does not report the session again.
    let data = p.seal_from_a(b"ping2");
    assert!(!p.deliver_to_b(&data).session_established);
}

#[test]
fn psk_pairs_interoperate_and_mismatches_fail() {
    // Matching PSK works.
    let mut p = new_pair_with(5, Some([7u8; 32]), None);
    p.establish();
    p.assert_roundtrip_a_to_b(b"psk traffic");

    // Mismatched PSK: responder produces a response the initiator rejects
    // (the responder cannot detect it; psk2 only enters at the response).
    let now = p.clock.now();
    let mut rng = wireguard_sans_io::testing::DeterministicRng::new(6);
    let (a_key, a_pub) = common::keypair(&mut rng);
    let (b_key, b_pub) = common::keypair(&mut rng);
    let mut a = common::side(
        a_key,
        b_pub,
        a_addr(),
        Some(b_addr()),
        Some([1; 32]),
        None,
        &mut rng,
    );
    let mut b = common::side(
        b_key,
        a_pub,
        b_addr(),
        Some(a_addr()),
        Some([2; 32]),
        None,
        &mut rng,
    );
    let init = a.initiate(now, &mut rng);
    let resp = match b.recv_from(now, a_addr(), false, &init, &mut rng).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        a.recv_from(now, b_addr(), false, &resp, &mut rng).rx,
        Rx::Dropped(DropReason::AuthFailure)
    );
    assert!(!a.is_established(now));
    assert_eq!(a.tunnel.stats().auth_failures, 1);
}

#[test]
fn padding_is_transparent_with_ip_length_helper() {
    let mut p = new_pair(7);
    p.establish();
    // A 21-byte "IPv4 packet": header claims total length 21.
    let mut packet = vec![0u8; 21];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&21u16.to_be_bytes());
    packet[20] = 0xfe;
    let wire = p.seal_from_a(&packet);
    let padded = p.open_at_b(&wire);
    assert_eq!(padded.len(), 32, "21 pads to 32");
    let inner = ip_packet_len(&padded).unwrap();
    assert_eq!(&padded[..inner], packet.as_slice());
}

#[test]
fn buffer_too_small_paths_are_total_and_change_nothing() {
    let mut p = new_pair(8);
    let now = p.clock.now();

    // poll: an initiation needs 148 bytes. The request stays due.
    p.a.tunnel.request_handshake(now);
    let mut tiny = [0u8; 147];
    assert!(matches!(
        p.a.tunnel.poll(now, &mut tiny, &mut p.rng),
        Err(Error::BufferTooSmall)
    ));
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 0);
    let init = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };

    // handle_initiation: a response needs 92 bytes. Nothing is consumed:
    // the same initiation is accepted afterwards.
    {
        let mut copy = init.clone();
        let mut tiny = [0u8; 91];
        let r = p.b.device.receive_for(
            &mut p.b.tunnel,
            now,
            a_addr(),
            false,
            &mut copy,
            &mut tiny,
            &mut p.rng,
        );
        assert!(matches!(r, Err(Error::BufferTooSmall)));
        assert_eq!(p.b.tunnel.stats().handshakes_responded, 0);
    }
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);

    // poll: a keepalive needs 32 bytes. It stays due.
    let mut tiny = [0u8; 31];
    assert!(matches!(
        p.a.tunnel.poll(now, &mut tiny, &mut p.rng),
        Err(Error::BufferTooSmall)
    ));
    assert_eq!(p.a.tunnel.stats().tx_transport, 0);
    assert!(matches!(
        p.a.poll(now, &mut p.rng),
        Polled::Transmit(_, SendReason::Keepalive, _)
    ));

    // encapsulate: transport needs padded(payload) + 32. No counter is
    // consumed by the failed attempt.
    let mut tiny = [0u8; 47];
    assert!(matches!(
        p.a.tunnel.encapsulate(now, b"0123456789abcdef", &mut tiny),
        Err(Error::BufferTooSmall)
    ));
    let mut tiny = [0u8; 47];
    assert!(matches!(
        p.a.tunnel.encapsulate_in_place(now, &mut tiny, 16),
        Err(Error::BufferTooSmall)
    ));
    let wire = p.seal_from_a(b"0123456789abcdef");
    assert_eq!(
        peek(&wire).unwrap(),
        PacketKind::TransportData {
            receiver_index: u32::from_le_bytes(wire[4..8].try_into().unwrap()),
            counter: 1, // 0 was the keepalive; the failed calls used none
        }
    );
}

#[test]
fn encapsulate_in_place_matches_the_copying_path() {
    // Two identical pairs (same seed ⇒ same keys, same counters): one
    // sends with `encapsulate`, the other with `encapsulate_in_place`.
    let mut p = new_pair(31);
    let mut q = new_pair(31);
    p.establish();
    q.establish();
    let now = p.clock.now();
    for len in [0usize, 1, 15, 16, 17, 100, 1419, 1420] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
        let copied = p.seal_from_a(&payload);

        // Dirty buffer: stale bytes where the header, padding and tag go.
        let mut buf = vec![0xEEu8; len + 64];
        buf[16..16 + len].copy_from_slice(&payload);
        let in_place = match q.a.tunnel.encapsulate_in_place(now, &mut buf, len).unwrap() {
            Encapsulated::Transport(tx) => {
                assert_eq!(tx.dst, b_addr());
                tx.datagram.to_vec()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(copied, in_place, "len={len}");
        // And the peer decrypts it, with zero padding.
        match q.deliver_to_b(&in_place).rx {
            Rx::Data(d) => {
                assert_eq!(&d[..len], payload.as_slice());
                assert!(d[len..].iter().all(|&b| b == 0), "padding must be zeroed");
            }
            Rx::Keepalive => assert_eq!(len, 0),
            other => panic!("{other:?}"),
        }
    }
    // Without a session the buffer is left alone.
    let mut r = new_pair(32);
    let mut buf = vec![0xEEu8; 128];
    assert!(matches!(
        r.a.tunnel.encapsulate_in_place(now, &mut buf, 40).unwrap(),
        Encapsulated::NoSession
    ));
    assert!(buf.iter().all(|&b| b == 0xEE));
}

#[test]
fn received_data_is_decrypted_in_place() {
    let mut p = new_pair(33);
    p.establish();
    let wire = p.seal_from_a(b"in place, no second buffer");
    let now = p.clock.now();
    let mut datagram = wire.clone();
    let mut out = [0u8; 92];
    let handled =
        p.b.device
            .receive_for(
                &mut p.b.tunnel,
                now,
                a_addr(),
                false,
                &mut datagram,
                &mut out,
                &mut p.rng,
            )
            .unwrap();
    match handled.received {
        wireguard_sans_io::Received::Data(d) => {
            assert_eq!(&d[..26], b"in place, no second buffer");
            assert_eq!(d.len(), 32);
        }
        other => panic!("{other:?}"),
    }
    // The plaintext sits right behind the 16-byte header of the datagram
    // the caller passed in; the header is untouched.
    assert_eq!(&datagram[..16], &wire[..16]);
    assert_eq!(&datagram[16..42], b"in place, no second buffer");
}

#[test]
fn peek_classifies_all_four_message_types() {
    let mut p = new_pair(9);
    let now = p.clock.now();
    let init = p.a_initiates();
    let init_index = match peek(&init).unwrap() {
        PacketKind::HandshakeInitiation { sender_index } => sender_index,
        other => panic!("{other:?}"),
    };
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    match peek(&resp).unwrap() {
        PacketKind::HandshakeResponse { receiver_index, .. } => {
            // The response routes back by our initiation's sender index.
            assert_eq!(receiver_index, init_index);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let data = p.seal_from_a(b"zz");
    assert!(matches!(
        peek(&data).unwrap(),
        PacketKind::TransportData { counter: 0, .. }
    ));
    // Cookie reply (B under load answers a second initiation).
    let later = p.clock.advance(6 * common::S);
    let init2 = p.a.initiate(later, &mut p.rng);
    let cookie = match p.b.recv_from(later, a_addr(), true, &init2, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        peek(&cookie).unwrap(),
        PacketKind::CookieReply {
            receiver_index: match peek(&init2).unwrap() {
                PacketKind::HandshakeInitiation { sender_index } => sender_index,
                _ => unreachable!(),
            }
        }
    );
    assert_eq!(peek(&[]), Err(DropReason::Malformed));
    let _ = now;
}

#[test]
fn sessions_rotate_and_old_session_still_decrypts_in_flight_packets() {
    let mut p = new_pair(10);
    p.establish();
    // Capture a datagram on session 1, then rekey, then deliver it late.
    let old_wire = p.seal_from_a(b"in flight from session one");
    p.clock.advance(common::S * 10);
    // Force a second handshake (A initiates explicitly).
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    // New session works A→B...
    p.assert_roundtrip_a_to_b(b"fresh session traffic");
    // ...and the late packet from the previous session still decrypts.
    let got = p.open_at_b(&old_wire);
    assert_eq!(&got[..26], b"in flight from session one");
    assert_eq!(p.b.tunnel.stats().handshakes_completed, 2);
}

#[test]
fn every_datagram_carries_its_destination() {
    let mut p = new_pair(34);
    let now = p.clock.now();
    // Initiation → the configured endpoint.
    p.a.tunnel.request_handshake(now);
    let mut buf = [0u8; 256];
    let init = match p.a.tunnel.poll(now, &mut buf, &mut p.rng).unwrap() {
        PollOutput::Transmit(tx, SendReason::HandshakeInitiation) => {
            assert_eq!(tx.dst, b_addr());
            tx.datagram.to_vec()
        }
        other => panic!("{other:?}"),
    };
    // Response → wherever the (authenticated) initiation came from, even
    // if that is not the configured endpoint.
    let roamed: std::net::SocketAddr = "198.51.100.77:1234".parse().unwrap();
    let mut copy = init.clone();
    let mut out = [0u8; 128];
    let handled =
        p.b.device
            .receive_for(
                &mut p.b.tunnel,
                now,
                roamed,
                false,
                &mut copy,
                &mut out,
                &mut p.rng,
            )
            .unwrap();
    match handled.received {
        wireguard_sans_io::Received::HandshakeResponse(tx) => assert_eq!(tx.dst, roamed),
        other => panic!("{other:?}"),
    }
    // The endpoint B knows is not given up for an initiation (it moves
    // when the peer uses the session): what B sends of its own accord
    // still goes to the configured address.
    assert!(!handled.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}
