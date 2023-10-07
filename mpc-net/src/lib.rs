use std::{
    net::{SocketAddr, TcpStream},
    sync::Mutex,
};

use lazy_static::lazy_static;

lazy_static! {
    static ref CONNECTIONS: Mutex<Connections> = Mutex::new(Connections::default());
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

#[derive(Default, Debug)]
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

