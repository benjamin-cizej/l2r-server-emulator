mod init;
pub use init::InitPacket;

pub trait FromDecryptedPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> std::io::Result<Self>
    where
        Self: Sized;
}
