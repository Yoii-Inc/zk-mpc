use std::{
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Mutex,
};

use ark_std::{end_timer, start_timer};
use lazy_static::lazy_static;
use log::debug;
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

lazy_static! {
    static ref CONNECTIONS: Mutex<Connections> = Mutex::new(Connections::default());
}

/// Macro for locking the FieldChannel singleton in the current scope.
macro_rules! get_ch {
    () => {
        CONNECTIONS.lock().expect("Poisoned FieldChannel")
    };
}

#[derive(Debug)]
struct Peer {
    id: usize,
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            id: 0,
            addr: "127.0.0.1:8000".parse().unwrap(),
            stream: None,
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
struct Connections {
    id: usize,
    peers: Vec<Peer>,
    stats: Stats,
}

impl Connections {
    /// Given a path and the `id` of oneself, initialize the structure
    fn init_from_path(&mut self, path: &str, id: usize) {
        let file = File::open(path).expect("Could not open file");
        let reader = BufReader::new(file);
        let mut addrs = Vec::new();
        for line in reader.lines() {
            let line = line.expect("Could not read line");
            let addr = line.parse().expect("Could not parse address");
            addrs.push(addr);
        }
        self.init_from_addrs(&addrs, id);
    }
    fn init_from_addrs(&mut self, addr: &[SocketAddr], id: usize) {
        for (peer_id, addr) in addr.iter().enumerate() {
            let peer = Peer {
                id: peer_id,
                addr: *addr,
                stream: None,
            };
            self.peers.push(peer);
        }
        assert!(id < self.peers.len());
        self.id = id;
    }
    fn connect_to_all(&mut self) {
        let timer = start_timer!(|| "Connecting");
        let n = self.peers.len();
        for from_id in 0..n {
            for to_id in (from_id + 1)..n {
                debug!("{} to {}", from_id, to_id);
                if self.id == from_id {
                    let to_addr = self.peers[to_id].addr;
                    debug!("Contacting {}", to_id);
                    let stream = loop {
                        let mut ms_waited = 0;
                        match TcpStream::connect(to_addr) {
                            Ok(s) => break s,
                            Err(e) => match e.kind() {
                                std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset => {
                                    ms_waited += 10;
                                    std::thread::sleep(std::time::Duration::from_millis(10));
                                    if ms_waited % 3_000 == 0 {
                                        debug!("Still waiting");
                                    } else if ms_waited > 30_000 {
                                        panic!("Could not find peer in 30s");
                                    }
                                }
                                _ => {
                                    panic!("Error during FieldChannel::new: {}", e);
                                }
                            },
                        }
                    };
                    stream.set_nodelay(true).unwrap();
                    self.peers[to_id].stream = Some(stream);
                } else if self.id == to_id {
                    debug!("Awaiting {}", from_id);
                    let listener = TcpListener::bind(self.peers[self.id].addr).unwrap();
                    let (stream, _addr) = listener.accept().unwrap();
                    stream.set_nodelay(true).unwrap();
                    self.peers[from_id].stream = Some(stream);
                }
            }
            // Sender for next round waits for note from this sender to prevent race on receipt.
            if from_id + 1 < n {
                if self.id == from_id {
                    self.peers[self.id + 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .write_all(&[0u8])
                        .unwrap();
                } else if self.id == from_id + 1 {
                    self.peers[self.id - 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .read_exact(&mut [0u8])
                        .unwrap();
                }
            }
        }
        // Do a round with the king, to be sure everyone is ready
        let from_all = self.send_to_king(&[self.id as u8]);
        self.recv_from_king(from_all);
        for id in 0..n {
            if id != self.id {
                assert!(self.peers[id].stream.is_some());
            }
        }
        end_timer!(timer);
    }
    fn am_king(&self) -> bool {
        self.id == 0
    }
    fn broadcast(&mut self, bytes_out: &[u8]) -> Vec<Vec<u8>> {
        let timer = start_timer!(|| format!("Broadcast {}", bytes_out.len()));
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
        end_timer!(timer);
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
                .stream
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
            let stream = self.peers[0].stream.as_mut().unwrap();
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
            p.stream = None;
        }
    }
}

pub trait MpcNet {
    /// Am I the first party?
    #[inline]
    fn am_king() -> bool {
        Self::party_id() == 0
    }
    /// How many parties are there?
    fn n_parties() -> usize;
    /// What is my party number (0 to n-1)?
    fn party_id() -> usize;
    /// Initialize the network layer from a file.
    /// The file should contain one HOST:PORT setting per line, corresponding to the addresses of
    /// the parties in increasing order.
    ///
    /// Parties are zero-indexed.
    fn init_from_file(path: &str, party_id: usize);
    fn init_from_addrs(adds: &[SocketAddr], party_id: usize);
    /// Is the network layer initalized?
    fn is_init() -> bool;
    /// Uninitialize the network layer, closing all connections.
    fn deinit();
    /// Set statistics to zero.
    fn reset_stats();
    /// Get statistics.
    fn stats() -> Stats;
    /// All parties send bytes to each other.
    fn broadcast_bytes(bytes: &[u8]) -> Vec<Vec<u8>>;
    /// All parties send bytes to the king.
    fn send_bytes_to_king(bytes: &[u8]) -> Option<Vec<Vec<u8>>>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    fn recv_bytes_from_king(bytes: Option<Vec<Vec<u8>>>) -> Vec<u8>;

    /// Everyone sends bytes to the king, who recieves those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.
    #[inline]
    fn king_compute(bytes: &[u8], f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
        let king_response = Self::send_bytes_to_king(bytes).map(f);
        Self::recv_bytes_from_king(king_response)
    }
}

pub struct MpcMultiNet;

impl MpcNet for MpcMultiNet {
    #[inline]
    fn party_id() -> usize {
        get_ch!().id
    }

    #[inline]
    fn n_parties() -> usize {
        get_ch!().peers.len()
    }

    #[inline]
    fn init_from_file(path: &str, party_id: usize) {
        let mut ch = get_ch!();
        ch.init_from_path(path, party_id);
        ch.connect_to_all();
    }

    #[inline]
    fn init_from_addrs(adds: &[SocketAddr], party_id: usize) {
        let mut ch = get_ch!();
        ch.init_from_addrs(adds, party_id);
        ch.connect_to_all();
    }

    #[inline]
    fn is_init() -> bool {
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
    fn broadcast_bytes(bytes: &[u8]) -> Vec<Vec<u8>> {
        get_ch!().broadcast(bytes)
    }

    #[inline]
    fn send_bytes_to_king(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
        get_ch!().send_to_king(bytes)
    }

    #[inline]
    fn recv_bytes_from_king(bytes: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        get_ch!().recv_from_king(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    lazy_static! {
        static ref PORT_LOCK: Mutex<()> = Mutex::new(());
    }

    fn get_free_port() -> SocketAddr {
        let _guard = PORT_LOCK.lock().unwrap();
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }
    #[test]
    fn test_connections_init_from_path() {
        let addr1 = get_free_port();
        let addr2 = get_free_port();

        let file_path = "test_init_from_path.txt";
        let content = format!("{}\n{}", addr1, addr2);
        std::fs::write(file_path, content).unwrap();

        let mut connections = Connections::default();
        connections.init_from_path(file_path, 0);
        assert_eq!(connections.peers.len(), 2);
        assert_eq!(connections.peers[0].addr, addr1);
        assert_eq!(connections.peers[1].addr, addr2);

        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_connections_init_from_addrs() {
        let addr3 = get_free_port();
        let addr4 = get_free_port();

        let addrs = [addr3, addr4];

        let mut connections = Connections::default();
        connections.init_from_addrs(&addrs, 1);
        assert_eq!(connections.peers.len(), 2);
        assert_eq!(connections.peers[0].addr, addr3);
        assert_eq!(connections.peers[1].addr, addr4);
    }

    #[test]
    fn test_send_recv_from_king() {
        // 2つのアドレスを取得して、ネットワークを2つのパーティで初期化
        let addr5 = get_free_port();
        let addr6 = get_free_port();

        let addrs = [addr5, addr6];

        MpcMultiNet::init_from_addrs(&addrs, 0);
        MpcMultiNet::init_from_addrs(&addrs, 1);

        let data = b"Hello, King!";
        let response = MpcMultiNet::send_bytes_to_king(data);

        assert_eq!(response, None);

        let expected_bytes: Vec<Vec<u8>> = vec![data.to_vec()];
        let recv_data = MpcMultiNet::recv_bytes_from_king(Some(expected_bytes));

        assert_eq!(recv_data, data);
    }

    #[test]
    fn test_stats_reset() {
        let stats = MpcMultiNet::stats();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.broadcasts, 0);
        assert_eq!(stats.to_king, 0);
        assert_eq!(stats.from_king, 0);

        {
            let mut ch = get_ch!();
            ch.stats.bytes_sent = 50;
        }

        MpcMultiNet::reset_stats();
        let stats = MpcMultiNet::stats();
        assert_eq!(stats.bytes_sent, 0);
    }

    // TODO: failing
    #[test]
    fn test_broadcast() {
        let addr1 = get_free_port();
        let addr2 = get_free_port();

        let addrs = [addr1, addr2];

        MpcMultiNet::init_from_addrs(&addrs, 0);
        MpcMultiNet::init_from_addrs(&addrs, 1);

        let data = b"Broadcast data";
        let received_data = MpcMultiNet::broadcast_bytes(data);

        for rdata in received_data {
            assert_eq!(rdata, data);
        }
    }
}
