mod connect_fail;
mod connect_ok;
mod init;

pub use connect_fail::ConnectFailPacket;
pub use connect_fail::ConnectFailReason;
pub use connect_ok::ConnectOkPacket;
pub use init::InitPacket;
use std::io;

pub trait FromDecryptedPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> io::Result<Self>
    where
        Self: Sized;
}

pub trait ServerPacketBytes {
    fn to_bytes(&self) -> io::Result<Vec<u8>>;
}
