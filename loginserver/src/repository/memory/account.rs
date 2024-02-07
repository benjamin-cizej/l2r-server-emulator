use crate::repository::account::AccountRepository;
use crate::structs::account::Account;
use std::collections::HashMap;

pub struct MemoryAccountRepository {
    accounts: HashMap<String, Account>,
}

impl MemoryAccountRepository {
    pub fn new() -> Self {
        MemoryAccountRepository {
            accounts: HashMap::new(),
        }
    }
}

impl AccountRepository for MemoryAccountRepository {
    fn get(&self, username: &String) -> std::io::Result<Option<&Account>> {
        Ok(self.accounts.get(username))
    }

    fn save(&mut self, account: &Account) -> std::io::Result<()> {
        self.accounts
            .insert(account.username.clone(), account.clone());
        Ok(())
    }

    fn count_all(&self) -> std::io::Result<usize> {
        Ok(self.accounts.len())
    }
}
