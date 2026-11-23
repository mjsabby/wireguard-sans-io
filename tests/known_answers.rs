//! Known answers for the handshake and the first transport messages.
//!
//! Every other test of the protocol has this library at both ends, and
//! two ends that share a mistake agree with each other. Here the other
//! end is `scripts/handshake_model.py`: an implementation of whitepaper
//! §5.4.2 – §5.4.6 on the Python standard library alone (X25519, ChaCha20
//! and Poly1305 as the RFCs' reference arithmetic on integers; BLAKE2s
//! and HMAC from `hashlib`), written from the documents and sharing
//! nothing with this code. What it computes for the inputs below is in
//! this file; the library has to produce the same bytes, message for
//! message.
//!
//! The inputs: fixed static keys and pre-shared key, ephemeral keys that
//! a scripted entropy source hands out, a fixed time. The one thing the
//! model is told rather than computes is the two session indices, which
//! each side chooses by a scheme of its own (`src/index.rs`, which has
//! its own known answers): they are read off the messages. If the way
//! indices are made changes, the expected bytes change with them — run
//! the script with the indices this test prints, and replace them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{a_addr, b_addr, id};
use wireguard_sans_io::{
    Device, Encapsulated, EntropyError, EntropySource, PeerConfig, PollOutput, PresharedKey,
    Received, StaticSecret, Ticks, WallClock,
};

/// An entropy source with nothing random about it: every request is
/// answered with `base, base + 1, …`. So the 32 bytes of an ephemeral
/// private key are known whatever else was drawn before them.
struct Scripted(u8);

impl EntropySource for Scripted {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        for (b, i) in buf.iter_mut().zip(0u8..) {
            *b = self.0.wrapping_add(i);
        }
        Ok(())
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let digit = |c: u8| (c as char).to_digit(16).unwrap() as u8;
    s.as_bytes()
        .chunks(2)
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect()
}

/// What the model computed.
struct Expected {
    initiator_index: u32,
    responder_index: u32,
    initiation: &'static str,
    response: &'static str,
    data_i: &'static str,
    data_r: &'static str,
}

const PAYLOAD_I: &[u8] = b"known answer: initiator to responder";
const PAYLOAD_R: &[u8] = b"and back";

fn index_of(message: &[u8]) -> u32 {
    u32::from_le_bytes(message[4..8].try_into().unwrap())
}

fn run(psk: Option<[u8; 32]>, expected: &Expected) {
    // The same inputs as in scripts/handshake_model.py.
    let s_priv_i: [u8; 32] = core::array::from_fn(|i| 0x01 + i as u8);
    let s_priv_r: [u8; 32] = core::array::from_fn(|i| 0xa1 + i as u8);
    let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0x1234_5678);
    let now = Ticks::from_secs(3);
    let (mut rng_i, mut rng_r) = (Scripted(0x40), Scripted(0x80));

    let secret_i = StaticSecret::from_bytes(s_priv_i);
    let secret_r = StaticSecret::from_bytes(s_priv_r);
    let (public_i, public_r) = (secret_i.public_key(), secret_r.public_key());
    assert_eq!(
        public_i.as_bytes().as_slice(),
        unhex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
    );
    assert_eq!(
        public_r.as_bytes().as_slice(),
        unhex("ad438bfae31f6c093d61d4339255ea798092c9fadd07b97827f4b0ae9dee7c1c")
    );
    let config = |peer, endpoint| {
        let mut config = PeerConfig::new(peer);
        if let Some(psk) = psk {
            config.psk = PresharedKey::from_bytes(psk);
        }
        config.endpoint = endpoint;
        config
    };
    let mut device_i = Device::new(secret_i, wall, &mut rng_i).unwrap();
    let mut device_r = Device::new(secret_r, wall, &mut rng_r).unwrap();
    let mut initiator = device_i
        .tunnel(id(1), config(public_r, Some(b_addr())), &mut rng_i)
        .unwrap();
    let mut responder = device_r
        .tunnel(id(2), config(public_i, None), &mut rng_r)
        .unwrap();

    // ---- the initiation (§5.4.2)
    initiator.request_handshake(now);
    let mut out = [0u8; 256];
    let mut initiation = match initiator.poll(now, &mut out, &mut rng_i).unwrap() {
        PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let hint = |what: &str, i: u32, r: u32| {
        format!(
            "{what}: if the indices are what changed, the model's answers are\n  \
             scripts/handshake_model.py --initiator-index {i:#010x} --responder-index {r:#010x}"
        )
    };
    assert_eq!(
        initiation,
        unhex(expected.initiation),
        "{}",
        hint(
            "the initiation",
            index_of(&initiation),
            expected.responder_index
        )
    );
    assert_eq!(index_of(&initiation), expected.initiator_index);

    // ---- the response (§5.4.3)
    let mut out = [0u8; 256];
    let handled = device_r
        .receive_for(
            &mut responder,
            now,
            a_addr(),
            false,
            &mut initiation,
            &mut out,
            &mut rng_r,
        )
        .unwrap();
    let mut response = match handled.received {
        Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        response,
        unhex(expected.response),
        "{}",
        hint(
            "the response",
            expected.initiator_index,
            index_of(&response)
        )
    );
    assert_eq!(index_of(&response), expected.responder_index);
    let mut out = [0u8; 256];
    let handled = device_i
        .receive_for(
            &mut initiator,
            now,
            b_addr(),
            false,
            &mut response,
            &mut out,
            &mut rng_i,
        )
        .unwrap();
    assert!(matches!(handled.received, Received::HandshakeComplete));

    // ---- transport data, both ways (§5.4.5, §5.4.6)
    let mut wire = [0u8; 256];
    let mut data_i = match initiator.encapsulate(now, PAYLOAD_I, &mut wire).unwrap() {
        Encapsulated::Transport(tx) => tx.datagram.to_vec(),
        _ => panic!("the initiator has a session"),
    };
    assert_eq!(data_i, unhex(expected.data_i), "initiator's first data");
    let mut out = [0u8; 256];
    let handled = device_r
        .receive_for(
            &mut responder,
            now,
            a_addr(),
            false,
            &mut data_i,
            &mut out,
            &mut rng_r,
        )
        .unwrap();
    match handled.received {
        // Padded to a multiple of 16 bytes with zeros.
        Received::Data(payload) => {
            assert_eq!(payload.len(), 48);
            assert_eq!(&payload[..PAYLOAD_I.len()], PAYLOAD_I);
            assert!(payload[PAYLOAD_I.len()..].iter().all(|b| *b == 0));
        }
        other => panic!("{other:?}"),
    }
    let mut wire = [0u8; 256];
    let data_r = match responder.encapsulate(now, PAYLOAD_R, &mut wire).unwrap() {
        Encapsulated::Transport(tx) => tx.datagram.to_vec(),
        _ => panic!("the responder has a session"),
    };
    assert_eq!(data_r, unhex(expected.data_r), "responder's first data");
}

#[test]
fn handshake_and_first_data_with_a_preshared_key() {
    run(
        Some([0x77; 32]),
        &Expected {
            initiator_index: 0xbcdbced0,
            responder_index: 0xc895f43f,
            initiation: "01000000d0cedbbc79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a5d48bfb8e56f5ff1e6e53296f4f6a895ca95d351c07707c88f4232a2f07b1a0e3f984ae1c959d330a92dc32a44219f0f1bd6b969a384fa635398568e2066cc2a508736769ff174e6949a6849de96ed799ca159b7489b90b778521a9100000000000000000000000000000000",
            response: "020000003ff495c8d0cedbbc493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531dcf6d7546c21ed32aa4e7256760187113d928bd5e860503b0ef1182314a5fbbc200000000000000000000000000000000",
            data_i: "040000003ff495c800000000000000008e46dec5f8bee9df017d4aeacc27d6186768105dc5ae1ffb541baef7bb48d43a9fac394e0fe144181f489ad91feb93415f5349adf6a881663613f01056d12b37",
            data_r: "04000000d0cedbbc00000000000000005fcc20a619e249c74d6a42b28afefa157c073bca5f7705b2b16c2864a507d93d",
        },
    );
}

#[test]
fn handshake_and_first_data_without_a_preshared_key() {
    run(
        None,
        &Expected {
            initiator_index: 0xbcdbced0,
            responder_index: 0xc895f43f,
            initiation: "01000000d0cedbbc79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a5d48bfb8e56f5ff1e6e53296f4f6a895ca95d351c07707c88f4232a2f07b1a0e3f984ae1c959d330a92dc32a44219f0f1bd6b969a384fa635398568e2066cc2a508736769ff174e6949a6849de96ed799ca159b7489b90b778521a9100000000000000000000000000000000",
            response: "020000003ff495c8d0cedbbc493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d32b96c7d68cbb3c003b2bc89988ee31137ecf260b1f8ea76811a0d5f3936401a00000000000000000000000000000000",
            data_i: "040000003ff495c80000000000000000856aefd370b3e44134fb6d808e63adc1f2e39b3acd43416009d738782de1b2fbb0b469a7fed650b670a04d4aca0644cf69e5bb138b0469b4bfadd9030d4e6f3c",
            data_r: "04000000d0cedbbc000000000000000033a394af8d8de8141a6b7025921586fbabfbf92b6d8099289c752d694e2451b3",
        },
    );
}
