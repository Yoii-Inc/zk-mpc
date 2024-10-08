use ark_std::{end_timer, perf_trace::TimerInfo, start_timer};
use async_smux::MuxStream;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{MPCNetError, MpcNet};

pub type WrappedMuxStream<T> = Framed<MuxStream<T>, LengthDelimitedCodec>;

struct Peer<IO: AsyncRead + AsyncWrite + Unpin> {
    id: usize,
    listen_addr: SocketAddr,
    streams: Option<Vec<TokioMutex<WrappedMuxStream<IO>>>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Debug for Peer<IO> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Peer");
        f.field("id", &self.id);
        f.field("listen_addr", &self.listen_addr);
        f.field("streams", &self.streams.is_some());
        f.finish()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Clone for Peer<IO> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            listen_addr: self.listen_addr,
            streams: None,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub broadcasts: usize,
    pub to_king: usize,
    pub from_king: usize,
}

#[derive(Default, Debug)]
struct MPCNetConnection<IO: AsyncRead + AsyncWrite + Unpin> {
    pub id: usize,
    pub listener: Option<TcpListener>,
    pub peers: HashMap<usize, Peer<IO>>,
    pub n_parties: usize,
    pub upload: AtomicUsize,
    pub download: AtomicUsize,
}

impl MPCNetConnection<TcpStream> {
    /// Given a path and the `id` of oneself, initialize the structure
    fn init_from_path(path: &str, id: usize) -> Self {
        let mut this = MPCNetConnection {
            id: 0,
            listener: None,
            peers: Default::default(),
            n_parties: 0,
            upload: AtomicUsize::new(0),
            download: AtomicUsize::new(0),
        };
        let f = BufReader::new(File::open(path).expect("host configuration path"));
        let mut peer_id = 0;
        for line in f.lines() {
            let line = line.unwrap();
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let addr: SocketAddr = trimmed
                    .parse()
                    .unwrap_or_else(|e| panic!("bad socket address: {}:\n{}", trimmed, e));
                let peer = Peer {
                    id: peer_id,
                    listen_addr: addr,
                    streams: None,
                };
                this.peers.insert(peer_id, peer);
                peer_id += 1;
            }
        }
        assert!(id < this.peers.len());
        this.id = id;
        this.n_parties = this.peers.len();
        this
    }

    pub async fn listen(&mut self) -> Result<(), MPCNetError> {
        let listen_addr = self.peers.get(&self.id).unwrap().listen_addr;
        let listener = TcpListener::bind(listen_addr).await.unwrap();
        self.listener = Some(listener);
        Ok(())
    }

    async fn connect_to_all(&mut self) {
        let n_minus_1 = self.n_parties - 1;
        let self_id = self.id;
        let peer_addrs = self
            .peers
            .iter()
            .map(|(_, p)| p.listen_addr)
            .collect::<Vec<_>>();
    }

    fn am_king(&self) -> bool {
        self.id == 0
    }
    fn broadcast(&mut self, bytes_out: &[u8]) -> Vec<Vec<u8>> {
        let timer: TimerInfo;
        #[cfg(feature = "log_broadcast")]
        {
            timer = start_timer!(|| format!("Broadcast {}", bytes_out.len()));
        }
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.bytes_sent += (self.peers.len() - 1) * m;
        self.stats.bytes_recv += (self.peers.len() - 1) * m;
        self.stats.broadcasts += 1;
        let r = self
            .peers
            .par_iter_mut()
            .enumerate()
            .map(|(id, peer)| {
                let mut bytes_in = vec![0u8; m];
                match id.cmp(&own_id) {
                    std::cmp::Ordering::Less => {
                        let stream = peer.stream.as_mut().unwrap();
                        stream.read_exact(&mut bytes_in[..]).unwrap();
                        stream.write_all(bytes_out).unwrap();
                    }
                    std::cmp::Ordering::Equal => {
                        bytes_in.copy_from_slice(bytes_out);
                    }
                    std::cmp::Ordering::Greater => {
                        let stream = peer.stream.as_mut().unwrap();
                        stream.write_all(bytes_out).unwrap();
                        stream.read_exact(&mut bytes_in[..]).unwrap();
                    }
                }
                bytes_in
            })
            .collect();
        #[cfg(feature = "log_broadcast")]
        {
            end_timer!(timer);
        }
        r
    }
    fn send_to_king(&mut self, bytes_out: &[u8]) -> Option<Vec<Vec<u8>>> {
        let timer = start_timer!(|| format!("To king {}", bytes_out.len()));
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.to_king += 1;
        let r = if self.am_king() {
            self.stats.bytes_recv += (self.peers.len() - 1) * m;
            Some(
                self.peers
                    .par_iter_mut()
                    .enumerate()
                    .map(|(id, peer)| {
                        let mut bytes_in = vec![0u8; m];
                        if id == own_id {
                            bytes_in.copy_from_slice(bytes_out);
                        } else {
                            let stream = peer.stream.as_mut().unwrap();
                            stream.read_exact(&mut bytes_in[..]).unwrap();
                        };
                        bytes_in
                    })
                    .collect(),
            )
        } else {
            self.stats.bytes_sent += m;
            self.peers[0]
                .streams
                .as_mut()
                .unwrap()
                .write_all(bytes_out)
                .unwrap();
            None
        };
        end_timer!(timer);
        r
    }
    fn recv_from_king(&mut self, bytes_out: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        let own_id = self.id;
        self.stats.from_king += 1;
        if self.am_king() {
            let bytes_out = bytes_out.unwrap();
            let m = bytes_out[0].len();
            let timer = start_timer!(|| format!("From king {}", m));
            let bytes_size = (m as u64).to_le_bytes();
            self.stats.bytes_sent += (self.peers.len() - 1) * (m + 8);
            self.peers
                .par_iter_mut()
                .enumerate()
                .filter(|p| p.0 != own_id)
                .for_each(|(id, peer)| {
                    let stream = peer.stream.as_mut().unwrap();
                    assert_eq!(bytes_out[id].len(), m);
                    stream.write_all(&bytes_size).unwrap();
                    stream.write_all(&bytes_out[id]).unwrap();
                });
            end_timer!(timer);
            bytes_out[own_id].clone()
        } else {
            let stream = self.peers[0].streams.as_mut().unwrap();
            let mut bytes_size = [0u8; 8];
            stream.read_exact(&mut bytes_size).unwrap();
            let m = u64::from_le_bytes(bytes_size) as usize;
            self.stats.bytes_recv += m;
            let mut bytes_in = vec![0u8; m];
            stream.read_exact(&mut bytes_in).unwrap();
            bytes_in
        }
    }
    fn uninit(&mut self) {
        for p in &mut self.peers {
            p.streams = None;
        }
    }
}

pub struct MpcMultiNet;

impl MpcNet for MpcMultiNet {
    #[inline]
    fn party_id(&self) -> usize {
        get_ch!().id
    }

    #[inline]
    fn n_parties(&self) -> usize {
        get_ch!().peers.len()
    }

    #[inline]
    fn init_from_file(path: &str, party_id: usize) {
        let mut ch = get_ch!();
        MPCNetConnection::init_from_path(path, party_id);
        ch.connect_to_all();
    }

    #[inline]
    fn is_init(&self) -> bool {
        get_ch!()
            .peers
            .first()
            .map(|p| p.stream.is_some())
            .unwrap_or(false)
    }

    #[inline]
    fn deinit() {
        get_ch!().uninit()
    }

    #[inline]
    fn reset_stats() {
        get_ch!().stats = Stats::default();
    }

    #[inline]
    fn stats() -> crate::Stats {
        get_ch!().stats.clone()
    }

    #[inline]
    fn broadcast_bytes(&self, bytes: &[u8]) -> Vec<Vec<u8>> {
        get_ch!().broadcast(bytes)
    }

    #[inline]
    fn worker_send_or_leader_receive(&self, bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
        get_ch!().send_to_king(bytes)
    }

    #[inline]
    fn worker_receive_or_leader_send(&self, bytes: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        get_ch!().recv_from_king(bytes)
    }

    #[inline]
    fn uninit() {
        get_ch!().uninit()
    }
}
