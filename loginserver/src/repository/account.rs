use crate::structs::account::Account;
use std::io;

pub trait AccountRepository: Sized + Send + 'static {
    fn get(&self, username: &str) -> io::Result<Option<&Account>>;
    fn save(&mut self, account: &Account) -> io::Result<()>;
    fn count_all(&self) -> io::Result<usize>;
}
