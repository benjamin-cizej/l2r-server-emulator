use crate::repository::account::AccountRepository;
use crate::structs::account::Account;
use std::collections::HashMap;

#[derive(Default)]
pub struct InMemoryAccountRepository {
    accounts: HashMap<String, Account>,
}

impl AccountRepository for InMemoryAccountRepository {
    fn get(&self, username: &str) -> std::io::Result<Option<&Account>> {
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
