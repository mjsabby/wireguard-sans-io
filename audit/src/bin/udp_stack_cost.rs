//! What a UDP datagram costs on its way through the kernel, and what
//! there is to be had from not making one system call for each.
//!
//!   udp_stack_cost drain <per-call> <sender-threads> <payload> <seconds>
//!   udp_stack_cost send  <one|mmsg|gso> <payload> <seconds> [gro]
//!
//! `drain`: one thread empties a loopback socket that `sender-threads`
//! others fill as fast as they can — one datagram per `recvfrom`
//! (`per-call` 1), or up to `per-call` of them per `recvmmsg`. Says how
//! many it got a second.
//!
//! `send`: one thread sends to a socket that another reads — one
//! datagram per `sendto`, 32 per `sendmmsg`, or 32 as one train
//! (`UDP_SEGMENT`: the kernel takes the train through its stack once and
//! cuts it up at the far end). With `gro`, the reader asks for trains as
//! well (`UDP_GRO`) and gets them uncut.
//!
//! The driver in this repository makes one call per datagram, and the
//! question this answers is what it would gain by not doing so. On the
//! machine it was written on: nothing from `recvmmsg` or `sendmmsg` —
//! the cost is the datagram's trip through the stack, not the call — and
//! a factor of five from segmentation, of twelve to twenty-five with it
//! at both ends. `audit/README.md` has the figures.
//!
//! Linux only, and the one place in this repository's tools that calls
//! the C library itself: the safe wrappers the driver uses have neither
//! `recvmmsg` nor the two socket options.

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_stack_cost: Linux only");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::mem::{size_of, zeroed};
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const BATCH: usize = 32;
    const UDP_SEGMENT: libc::c_int = 103;
    const UDP_GRO: libc::c_int = 104;

    /// Run the calling thread on `cpu` (modulo what there is).
    fn pin(cpu: usize) {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        // SAFETY: a zeroed cpu_set_t is an empty set; CPU_SET writes
        // inside it; sched_setaffinity reads `size_of::<cpu_set_t>()`
        // bytes of it.
        unsafe {
            let mut set: libc::cpu_set_t = zeroed();
            libc::CPU_SET(cpu % cpus, &mut set);
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set);
        }
    }

    fn sockaddr(socket: &UdpSocket) -> libc::sockaddr_in {
        let std::net::SocketAddr::V4(v4) = socket.local_addr().unwrap() else {
            panic!("an IPv4 socket")
        };
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            },
            sin_zero: [0; 8],
        }
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("drain") => drain(
                args[2].parse().unwrap(),
                args[3].parse().unwrap(),
                args[4].parse().unwrap(),
                args[5].parse().unwrap(),
            ),
            Some("send") => send(
                &args[2],
                args[3].parse().unwrap(),
                args[4].parse().unwrap(),
                args.get(5).is_some_and(|s| s == "gro"),
            ),
            _ => eprintln!("usage: see the top of audit/src/bin/udp_stack_cost.rs"),
        }
    }

    fn drain(per_call: usize, senders: usize, payload: usize, secs: f64) {
        assert!((1..=64).contains(&per_call) && payload <= 2048);
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let to = receiver.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let threads: Vec<_> = (0..senders)
            .map(|i| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    pin(12 + i);
                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                    socket.set_nonblocking(true).unwrap();
                    let datagram = vec![0x5au8; payload];
                    while !stop.load(Ordering::Relaxed) {
                        let _ = socket.send_to(&datagram, to);
                    }
                })
            })
            .collect();
        pin(8);
        let fd = receiver.as_raw_fd();
        let mut bufs = vec![[0u8; 2048]; 64];
        // SAFETY: zeroed iovec, mmsghdr and sockaddr_storage are valid
        // (null pointers, zero lengths).
        let mut iov: Vec<libc::iovec> = vec![unsafe { zeroed() }; 64];
        let mut from: Vec<libc::sockaddr_storage> = vec![unsafe { zeroed() }; 64];
        let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { zeroed() }; 64];
        for i in 0..64 {
            iov[i].iov_base = bufs[i].as_mut_ptr().cast();
            iov[i].iov_len = bufs[i].len();
            msgs[i].msg_hdr.msg_iov = &mut iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = (&raw mut from[i]).cast();
        }
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let (mut got, mut calls) = (0u64, 0u64);
        while started.elapsed().as_secs_f64() < secs {
            for _ in 0..256 {
                calls += 1;
                if per_call == 1 {
                    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    // SAFETY: the buffer and the address are this
                    // function's, of the lengths given.
                    let n = unsafe {
                        libc::recvfrom(
                            fd,
                            bufs[0].as_mut_ptr().cast(),
                            bufs[0].len(),
                            0,
                            (&raw mut from[0]).cast(),
                            &mut len,
                        )
                    };
                    got += u64::from(n > 0);
                } else {
                    for msg in &mut msgs[..per_call] {
                        msg.msg_hdr.msg_namelen =
                            size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    }
                    // SAFETY: `per_call` headers, each pointing at a
                    // buffer and an address that live as long as `msgs`.
                    let n = unsafe {
                        libc::recvmmsg(
                            fd,
                            msgs.as_mut_ptr(),
                            per_call as libc::c_uint,
                            0,
                            std::ptr::null_mut(),
                        )
                    };
                    if n > 0 {
                        got += n as u64;
                    }
                }
            }
        }
        let took = started.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        for thread in threads {
            thread.join().unwrap();
        }
        println!(
            "drain  {per_call:>2} per call, {payload:>4} bytes: {:>9.0} datagrams/s, {:>4.0} ns each, {:.1} per call",
            got as f64 / took,
            took * 1e9 / got as f64,
            got as f64 / calls as f64,
        );
    }

    fn send(mode: &str, payload: usize, secs: f64, gro: bool) {
        assert!(payload <= 1472);
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        if gro {
            let on: libc::c_int = 1;
            // SAFETY: an int, by its length.
            let set = unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::IPPROTO_UDP,
                    UDP_GRO,
                    (&raw const on).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(set, 0, "UDP_GRO");
        }
        let mut to = sockaddr(&receiver);
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let reader = {
            let (stop, received) = (Arc::clone(&stop), Arc::clone(&received));
            std::thread::spawn(move || {
                pin(10);
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(n) = receiver.recv(&mut buf) {
                        received.0.fetch_add(n as u64, Ordering::Relaxed);
                        received.1.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };
        pin(8);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        let mut train = vec![0x5au8; payload * BATCH];
        // SAFETY: as in `drain`.
        let mut iov: Vec<libc::iovec> = vec![unsafe { zeroed() }; BATCH];
        let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { zeroed() }; BATCH];
        for (i, piece) in train.chunks_exact_mut(payload).enumerate() {
            iov[i].iov_base = piece.as_mut_ptr().cast();
            iov[i].iov_len = payload;
            msgs[i].msg_hdr.msg_iov = &mut iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = (&raw mut to).cast();
            msgs[i].msg_hdr.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        // One message for the whole train, with the size of a segment as
        // its control message.
        let mut whole = libc::iovec {
            iov_base: train.as_mut_ptr().cast(),
            iov_len: train.len(),
        };
        // SAFETY: CMSG_SPACE is arithmetic.
        let space = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: a zeroed msghdr is valid; the control buffer is large
        // enough for one header and a u16 (CMSG_SPACE above), so
        // CMSG_FIRSTHDR and CMSG_DATA point inside it.
        let mut segmented: libc::msghdr = unsafe { zeroed() };
        segmented.msg_name = (&raw mut to).cast();
        segmented.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        segmented.msg_iov = &mut whole;
        segmented.msg_iovlen = 1;
        segmented.msg_control = control.as_mut_ptr().cast();
        segmented.msg_controllen = space as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&segmented);
            (*header).cmsg_level = libc::SOL_UDP;
            (*header).cmsg_type = UDP_SEGMENT;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as _;
            libc::CMSG_DATA(header)
                .cast::<u16>()
                .write_unaligned(payload as u16);
        }

        let started = Instant::now();
        let (mut sent, mut failed) = (0u64, 0u64);
        while started.elapsed().as_secs_f64() < secs {
            for _ in 0..64 {
                match mode {
                    "one" => {
                        for piece in train.chunks_exact(payload) {
                            // SAFETY: a buffer and an address of the
                            // lengths given.
                            let n = unsafe {
                                libc::sendto(
                                    fd,
                                    piece.as_ptr().cast(),
                                    payload,
                                    0,
                                    (&raw const to).cast(),
                                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                                )
                            };
                            if n > 0 { sent += 1 } else { failed += 1 }
                        }
                    }
                    "mmsg" => {
                        // SAFETY: BATCH headers that point into `train`
                        // and at `to`.
                        let n = unsafe {
                            libc::sendmmsg(fd, msgs.as_mut_ptr(), BATCH as libc::c_uint, 0)
                        };
                        if n > 0 { sent += n as u64 } else { failed += 1 }
                    }
                    "gso" => {
                        // SAFETY: the header built above.
                        let n = unsafe { libc::sendmsg(fd, &segmented, 0) };
                        if n > 0 {
                            sent += BATCH as u64
                        } else {
                            failed += 1
                        }
                    }
                    other => panic!("mode {other}"),
                }
            }
        }
        let took = started.elapsed().as_secs_f64();
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        let (bytes, reads) = (
            received.0.load(Ordering::Relaxed),
            received.1.load(Ordering::Relaxed),
        );
        println!(
            "send   {mode:<4} {payload:>4} bytes{}: {:>9.0} datagrams/s, {:>4.0} ns each; the reader got {:.0} % of them, {:.0} bytes a read; {failed} calls failed",
            if gro { ", reader with UDP_GRO" } else { "" },
            sent as f64 / took,
            took * 1e9 / sent as f64,
            100.0 * bytes as f64 / (sent as f64 * payload as f64),
            bytes as f64 / reads.max(1) as f64,
        );
    }
}
