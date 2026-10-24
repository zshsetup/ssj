//! QUIC through a jump host that only forwards packets.
//!
//! The client speaks UDP to a relay on the jump host, and the relay passes the packets, one frame
//! each, to the server over a byte stream (the `ssh` channel to the host behind the jump). The QUIC
//! connection stays between client and server, with the pinned certificates, so the relay sees
//! ciphertext only.
//!
//! - [`Sealer`] and [`Opener`] put a counter and a tag on every datagram between the client and
//!   the relay. The relay thereby tells a packet of its client from anything else on its port, and
//!   follows the client to a new address without being fooled by a recorded packet.
//! - [`EnvelopeSocket`] is the UDP socket of the client endpoint.
//! - [`StreamSocket`] is the "UDP socket" of the server endpoint: it reads and writes frames on a
//!   byte stream.
//! - [`forward`] is the relay itself.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use ring::hmac;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

/// Bytes of the secret that the client and the relay share.
pub const SECRET_LEN: usize = 32;
/// Bytes that the envelope adds to a datagram: the counter and the tag.
pub const ENVELOPE_LEN: usize = COUNTER_LEN + TAG_LEN;
/// Largest datagram that passes: a QUIC packet is 1200 bytes or a little more.
pub const MAX_DATAGRAM: usize = 1500;

const COUNTER_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// Datagrams that wait for the stream to the server, or for the endpoint to take them.
const QUEUE: usize = 512;
/// Counters that a packet may trail the newest one by and still pass, as in WireGuard.
const WINDOW: u64 = 64;

/// A fresh secret for a client and its relay.
pub fn random_secret() -> io::Result<[u8; SECRET_LEN]> {
    let mut secret = [0u8; SECRET_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret)
        .map_err(|_| io::Error::other("no random numbers"))?;
    Ok(secret)
}

/// Which way a datagram goes. The tag covers it, so that a packet of one direction cannot be
/// replayed into the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ToServer = 1,
    ToClient = 2,
}

fn tag(
    key: &hmac::Key,
    direction: Direction,
    counter: [u8; COUNTER_LEN],
    payload: &[u8],
) -> hmac::Tag {
    let mut context = hmac::Context::with_key(key);
    context.update(&[direction as u8]);
    context.update(&counter);
    context.update(payload);
    context.sign()
}

/// Whether two tags are equal, in a time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Puts the envelope on the datagrams of one direction.
pub struct Sealer {
    key: hmac::Key,
    direction: Direction,
    counter: AtomicU64,
}

impl Sealer {
    pub fn new(secret: &[u8; SECRET_LEN], direction: Direction) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            direction,
            counter: AtomicU64::new(0),
        }
    }

    /// Writes counter, tag, and `payload` to `out`, which is cleared first.
    pub fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        // counters start at 1, so that 0 means "none yet" for the opener
        let counter = (self.counter.fetch_add(1, Ordering::Relaxed) + 1).to_be_bytes();
        let tag = tag(&self.key, self.direction, counter, payload);
        out.clear();
        out.extend_from_slice(&counter);
        out.extend_from_slice(&tag.as_ref()[..TAG_LEN]);
        out.extend_from_slice(payload);
    }
}

/// What [`Opener::open`] found in a datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened<'a> {
    pub payload: &'a [u8],
    /// The counter is higher than any before it. Only such a packet may move the address that the
    /// relay answers: a recorded packet is never the newest.
    pub newest: bool,
}

/// Checks the envelope on the datagrams of one direction.
pub struct Opener {
    key: hmac::Key,
    direction: Direction,
    /// The highest counter that passed, and a bit for each of the [`WINDOW`] before it.
    seen: Mutex<(u64, u64)>,
}

impl Opener {
    pub fn new(secret: &[u8; SECRET_LEN], direction: Direction) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            direction,
            seen: Mutex::new((0, 0)),
        }
    }

    /// The payload of a datagram that has a valid tag and a counter that was not used yet.
    pub fn open<'a>(&self, datagram: &'a [u8]) -> Option<Opened<'a>> {
        if datagram.len() < ENVELOPE_LEN {
            return None;
        }
        let (counter_bytes, rest) = datagram.split_at(COUNTER_LEN);
        let (their_tag, payload) = rest.split_at(TAG_LEN);
        let counter_bytes: [u8; COUNTER_LEN] = counter_bytes.try_into().ok()?;
        let ours = tag(&self.key, self.direction, counter_bytes, payload);
        if !same(&ours.as_ref()[..TAG_LEN], their_tag) {
            return None;
        }
        let counter = u64::from_be_bytes(counter_bytes);
        let mut seen = self.seen.lock().expect("not poisoned");
        let (highest, bits) = &mut *seen;
        let newest = counter > *highest;
        if newest {
            let shift = counter - *highest;
            *bits = if shift >= 64 { 0 } else { *bits << shift };
            *bits |= 1;
            *highest = counter;
        } else {
            let behind = *highest - counter;
            if counter == 0 || behind >= WINDOW || *bits & (1 << behind) != 0 {
                return None;
            }
            *bits |= 1 << behind;
        }
        Some(Opened { payload, newest })
    }
}

/// Reads the next frame of a byte stream: two bytes of length, then that many bytes. `Ok(None)` at
/// the end of the stream. A frame longer than [`MAX_DATAGRAM`] is an error, since no peer sends one.
pub async fn read_frame<R>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<()>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_DATAGRAM {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
    }
    buf.resize(length, 0);
    reader.read_exact(buf).await?;
    Ok(Some(()))
}

/// Writes one frame, in a single write, and flushes.
pub async fn write_frame<W>(writer: &mut W, datagram: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(datagram.len())
        .ok()
        .filter(|n| usize::from(*n) <= MAX_DATAGRAM)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "datagram too long"))?;
    let mut frame = Vec::with_capacity(2 + datagram.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(datagram);
    writer.write_all(&frame).await?;
    writer.flush().await
}

fn receive(
    meta: &mut [RecvMeta],
    bufs: &mut [IoSliceMut<'_>],
    datagram: &[u8],
    from: SocketAddr,
) -> bool {
    let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
        return false;
    };
    if datagram.len() > buf.len() {
        return false;
    }
    buf[..datagram.len()].copy_from_slice(datagram);
    *slot = RecvMeta {
        addr: from,
        len: datagram.len(),
        stride: datagram.len(),
        ecn: None,
        dst_ip: None,
    };
    true
}

/// The UDP socket of the client endpoint when the server is behind a relay: every datagram gets
/// the envelope, and what comes back is checked and unwrapped. QUIC sees the relay as the peer.
pub struct EnvelopeSocket {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    sealer: Arc<Sealer>,
    opener: Arc<Opener>,
}

impl fmt::Debug for EnvelopeSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeSocket")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Writable(Arc<UdpSocket>);

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

/// The secret and the counters of a client, which outlive a socket: after a change of the network
/// a new socket takes over with the counters going on, since the relay accepts no counter twice.
#[derive(Clone)]
pub struct RelayKeys {
    sealer: Arc<Sealer>,
    opener: Arc<Opener>,
}

impl RelayKeys {
    pub fn client(secret: &[u8; SECRET_LEN]) -> Self {
        Self {
            sealer: Arc::new(Sealer::new(secret, Direction::ToServer)),
            opener: Arc::new(Opener::new(secret, Direction::ToClient)),
        }
    }
}

impl EnvelopeSocket {
    /// A socket on `local` that sends to `relay` only.
    pub fn bind(local: SocketAddr, relay: SocketAddr, keys: &RelayKeys) -> io::Result<Arc<Self>> {
        let socket = std::net::UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        let socket = Arc::new(socket);
        Ok(Arc::new(Self {
            socket,
            relay,
            sealer: keys.sealer.clone(),
            opener: keys.opener.clone(),
        }))
    }
}

impl AsyncUdpSocket for EnvelopeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(self.socket.clone()))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut datagram = Vec::with_capacity(ENVELOPE_LEN + transmit.contents.len());
        self.sealer.seal(transmit.contents, &mut datagram);
        self.socket.try_send_to(&datagram, self.relay).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut datagram = [0u8; MAX_DATAGRAM + ENVELOPE_LEN];
        loop {
            ready!(self.socket.poll_recv_ready(cx))?;
            match self.socket.try_recv_from(&mut datagram) {
                Ok((n, from)) => {
                    if from != self.relay {
                        continue;
                    }
                    let Some(opened) = self.opener.open(&datagram[..n]) else {
                        continue;
                    };
                    if receive(meta, bufs, opened.payload, self.relay) {
                        return Poll::Ready(Ok(1));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                // the network says that an earlier packet had no way, which is no reason to stop
                Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // the largest packet is fixed at the size that QUIC starts with
        true
    }
}

/// The "UDP socket" of the server endpoint behind a relay: frames on a byte stream.
///
/// Datagrams that cannot go out or in at once are dropped, as a network drops them, so that a
/// stalled stream costs memory for [`QUEUE`] packets and no more.
pub struct StreamSocket {
    local: SocketAddr,
    peer: SocketAddr,
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    ended: watch::Receiver<bool>,
}

impl fmt::Debug for StreamSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamSocket")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StreamSocket {
    /// Starts the tasks that move frames between the stream and the socket. The peer address is
    /// the one that QUIC sees for the client; it is made up, since the packets come out of a pipe.
    /// Must run inside the tokio runtime.
    pub fn new<R, W>(mut reader: R, mut writer: W) -> Arc<Self>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (outgoing, mut to_stream) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (from_stream, incoming) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (end, ended) = watch::channel(false);
        let end_reading = end.clone();
        tokio::spawn(async move {
            let mut frame = Vec::new();
            while let Ok(Some(())) = read_frame(&mut reader, &mut frame).await {
                // a full queue drops the packet
                let _ = from_stream.try_send(frame.clone());
            }
            let _ = end_reading.send(true);
        });
        tokio::spawn(async move {
            while let Some(datagram) = to_stream.recv().await {
                if write_frame(&mut writer, &datagram).await.is_err() {
                    break;
                }
            }
            let _ = end.send(true);
        });
        Arc::new(Self {
            local: SocketAddr::from(([127, 0, 0, 1], 0)),
            peer: SocketAddr::from(([127, 0, 0, 1], 1)),
            outgoing,
            incoming: Mutex::new(incoming),
            ended,
        })
    }

    /// The address that QUIC sees for the client.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Resolves when the stream has ended in either direction. The endpoint is then of no use.
    pub async fn ended(&self) {
        let mut ended = self.ended.clone();
        let _ = ended.wait_for(|ended| *ended).await;
    }
}

impl AsyncUdpSocket for StreamSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.contents.len() <= MAX_DATAGRAM {
            // a full queue is a lost packet
            let _ = self.outgoing.try_send(transmit.contents.to_vec());
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut incoming = self.incoming.lock().expect("not poisoned");
        loop {
            match ready!(incoming.poll_recv(cx)) {
                Some(datagram) => {
                    if receive(meta, bufs, &datagram, self.peer) {
                        return Poll::Ready(Ok(1));
                    }
                }
                // the stream ended: nothing comes any more, and `ended` tells the owner
                None => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// How long a relay without a client packet stays up.
pub const IDLE: Duration = Duration::from_secs(30 * 60);

/// Runs the relay: datagrams from the client on `udp` go to the stream, and frames from the stream
/// go to the address that the newest valid datagram of the client came from.
///
/// Returns when the stream ends, or when the client has sent nothing for `idle`.
pub async fn forward<R, W>(
    udp: Arc<UdpSocket>,
    secret: &[u8; SECRET_LEN],
    mut reader: R,
    mut writer: W,
    idle: Duration,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let opener = Opener::new(secret, Direction::ToServer);
    let sealer = Sealer::new(secret, Direction::ToClient);
    let client: Mutex<Option<SocketAddr>> = Mutex::new(None);
    let heard = Mutex::new(Instant::now());

    let to_server = async {
        let mut datagram = vec![0u8; MAX_DATAGRAM + ENVELOPE_LEN];
        loop {
            let (n, from) = udp.recv_from(&mut datagram).await?;
            let Some(opened) = opener.open(&datagram[..n]) else {
                continue;
            };
            if opened.newest {
                *client.lock().expect("not poisoned") = Some(from);
            }
            *heard.lock().expect("not poisoned") = Instant::now();
            write_frame(&mut writer, opened.payload).await?;
        }
    };
    let to_client = async {
        let (mut frame, mut sealed) = (Vec::new(), Vec::new());
        while read_frame(&mut reader, &mut frame).await?.is_some() {
            let Some(to) = *client.lock().expect("not poisoned") else {
                continue;
            };
            sealer.seal(&frame, &mut sealed);
            // a datagram that does not leave is a lost packet
            let _ = udp.send_to(&sealed, to).await;
        }
        Ok::<(), io::Error>(())
    };
    let watch_idle = async {
        loop {
            let left = idle.saturating_sub(heard.lock().expect("not poisoned").elapsed());
            if left.is_zero() {
                return;
            }
            tokio::time::sleep(left).await;
        }
    };
    tokio::select! {
        result = to_server => result,
        result = to_client => result,
        () = watch_idle => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; SECRET_LEN] = [7; SECRET_LEN];

    fn pair() -> (Sealer, Opener) {
        (
            Sealer::new(&SECRET, Direction::ToServer),
            Opener::new(&SECRET, Direction::ToServer),
        )
    }

    fn sealed(sealer: &Sealer, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        sealer.seal(payload, &mut out);
        out
    }

    #[test]
    fn a_sealed_datagram_opens_to_its_payload() {
        let (sealer, opener) = pair();
        let datagram = sealed(&sealer, b"hello");
        assert_eq!(datagram.len(), 5 + ENVELOPE_LEN);
        let opened = opener.open(&datagram).unwrap();
        assert_eq!(opened.payload, b"hello");
        assert!(opened.newest);
    }

    #[test]
    fn a_changed_byte_does_not_open() {
        let (sealer, opener) = pair();
        let datagram = sealed(&sealer, b"hello");
        for at in 0..datagram.len() {
            let mut bad = datagram.clone();
            bad[at] ^= 1;
            assert!(opener.open(&bad).is_none(), "byte {at}");
        }
        assert!(opener.open(&datagram[..ENVELOPE_LEN - 1]).is_none());
        assert!(opener.open(&[]).is_none());
    }

    #[test]
    fn another_secret_or_direction_does_not_open() {
        let (sealer, _) = pair();
        let datagram = sealed(&sealer, b"hello");
        let other_secret = Opener::new(&[8; SECRET_LEN], Direction::ToServer);
        assert!(other_secret.open(&datagram).is_none());
        let other_direction = Opener::new(&SECRET, Direction::ToClient);
        assert!(other_direction.open(&datagram).is_none());
    }

    #[test]
    fn a_datagram_opens_once() {
        let (sealer, opener) = pair();
        let datagram = sealed(&sealer, b"hello");
        assert!(opener.open(&datagram).is_some());
        assert!(opener.open(&datagram).is_none());
    }

    #[test]
    fn a_late_datagram_opens_but_is_not_the_newest() {
        let (sealer, opener) = pair();
        let first = sealed(&sealer, b"1");
        let second = sealed(&sealer, b"2");
        assert!(opener.open(&second).unwrap().newest);
        let late = opener.open(&first).unwrap();
        assert!(!late.newest);
        assert_eq!(late.payload, b"1");
    }

    #[test]
    fn a_datagram_far_behind_does_not_open() {
        let (sealer, opener) = pair();
        let old = sealed(&sealer, b"old");
        for _ in 0..WINDOW {
            let datagram = sealed(&sealer, b"x");
            assert!(opener.open(&datagram).is_some());
        }
        assert!(opener.open(&old).is_none());
    }

    #[test]
    fn reversed_arrival_within_the_window_passes() {
        let (sealer, opener) = pair();
        let packets: Vec<Vec<u8>> = (0..10u8).map(|i| sealed(&sealer, &[i])).collect();
        for packet in packets.into_iter().rev() {
            assert!(opener.open(&packet).is_some());
        }
    }

    #[tokio::test]
    async fn frames_survive_a_byte_stream() {
        let (mut near, mut far) = tokio::io::duplex(64);
        let sent: Vec<Vec<u8>> = vec![vec![], vec![1], vec![2; 1200], vec![3; MAX_DATAGRAM]];
        let to_send = sent.clone();
        tokio::spawn(async move {
            for datagram in to_send {
                write_frame(&mut near, &datagram).await.unwrap();
            }
        });
        let mut frame = Vec::new();
        for datagram in sent {
            assert!(read_frame(&mut far, &mut frame).await.unwrap().is_some());
            assert_eq!(frame, datagram);
        }
        assert!(read_frame(&mut far, &mut frame).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_frame_that_is_too_long_is_refused() {
        let (mut near, mut far) = tokio::io::duplex(64);
        near.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
        let mut frame = Vec::new();
        assert!(read_frame(&mut far, &mut frame).await.is_err());
        assert!(
            write_frame(&mut near, &[0; MAX_DATAGRAM + 1])
                .await
                .is_err()
        );
    }
}
