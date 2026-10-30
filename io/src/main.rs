//! The vault node's only links to the outside world, inside the enclave (it has no network and no disk):
//!
//!   enclave-io attest --public-key HEX [--nonce HEX] [--user-data HEX]
//!       An attestation document from the Nitro Secure Module, base64 on stdout.
//!   enclave-io vsock-to-tcp VSOCK_PORT TCP_ADDR
//!       Calls to the node: the host connects to this enclave's vsock port, each connection goes to TCP_ADDR.
//!   enclave-io tcp-to-vsock TCP_ADDR CID:PORT
//!       Calls out (KMS, S3): a local port carried to the host's vsock-proxy. TLS runs end to end over it.
//!   enclave-io lo-up
//!       Brings the loopback interface up (a new enclave starts with it down).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::Engine;
use serde_bytes::ByteBuf;
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

fn arg(args: &[String], name: &str) -> Option<Vec<u8>> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|h| hex::decode(h).unwrap_or_else(|_| fail(&format!("{name} is not hex"))))
}

fn fail(msg: &str) -> ! {
    eprintln!("enclave-io: {msg}");
    std::process::exit(2)
}

fn attest(args: &[String]) {
    let fd = nsm_init();
    if fd < 0 {
        fail("no Nitro Secure Module (/dev/nsm): not in an enclave");
    }
    let req = Request::Attestation {
        public_key: arg(args, "--public-key").map(ByteBuf::from),
        nonce: arg(args, "--nonce").map(ByteBuf::from),
        user_data: arg(args, "--user-data").map(ByteBuf::from),
    };
    let res = nsm_process_request(fd, req);
    nsm_exit(fd);
    match res {
        Response::Attestation { document } => println!("{}", base64::engine::general_purpose::STANDARD.encode(document)),
        other => fail(&format!("the module refused: {other:?}")),
    }
}

/// Copies bytes both ways until either side closes.
fn pipe<A, B>(a: A, b: B, a2: A, b2: B)
where
    A: Read + Write + Send + 'static + Closable,
    B: Read + Write + Send + 'static + Closable,
{
    let up = thread::spawn(move || copy(a, b));
    copy(b2, a2);
    let _ = up.join();
}

trait Closable {
    fn close_write(&self);
}
impl Closable for TcpStream {
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}
impl Closable for VsockStream {
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

fn copy<R: Read, W: Write + Closable>(mut r: R, mut w: W) {
    let _ = io::copy(&mut r, &mut w);
    w.close_write();
}

fn vsock_to_tcp(port: u32, tcp: String) {
    let l = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port)).unwrap_or_else(|e| fail(&format!("vsock port {port}: {e}")));
    for conn in l.incoming().flatten() {
        let tcp = tcp.clone();
        thread::spawn(move || {
            if let Ok(t) = TcpStream::connect(&tcp) {
                if let (Ok(c2), Ok(t2)) = (conn.try_clone(), t.try_clone()) {
                    pipe(conn, t, c2, t2);
                }
            }
        });
    }
}

fn tcp_to_vsock(tcp: String, cid: u32, port: u32) {
    let l = TcpListener::bind(&tcp).unwrap_or_else(|e| fail(&format!("{tcp}: {e}")));
    for conn in l.incoming().flatten() {
        thread::spawn(move || {
            if let Ok(v) = VsockStream::connect(&VsockAddr::new(cid, port)) {
                if let (Ok(c2), Ok(v2)) = (conn.try_clone(), v.try_clone()) {
                    pipe(conn, v, c2, v2);
                }
            }
        });
    }
}

fn lo_up() {
    // SIOCGIFFLAGS / SIOCSIFFLAGS on "lo"; the kernel gives it 127.0.0.1 when it comes up.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            fail("socket");
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            fail("SIOCGIFFLAGS lo");
        }
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            fail("SIOCSIFFLAGS lo");
        }
        libc::close(fd);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("attest") => attest(&args),
        Some("lo-up") => lo_up(),
        Some("vsock-to-tcp") if args.len() == 4 => vsock_to_tcp(args[2].parse().unwrap_or_else(|_| fail("VSOCK_PORT")), args[3].clone()),
        Some("tcp-to-vsock") if args.len() == 4 => {
            let (cid, port) = args[3].split_once(':').unwrap_or_else(|| fail("CID:PORT"));
            tcp_to_vsock(args[2].clone(), cid.parse().unwrap_or_else(|_| fail("CID")), port.parse().unwrap_or_else(|_| fail("PORT")))
        }
        _ => fail("usage: lo-up | attest --public-key HEX [--nonce HEX] [--user-data HEX] | vsock-to-tcp VSOCK_PORT TCP_ADDR | tcp-to-vsock TCP_ADDR CID:PORT"),
    }
}
