use shared::chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct Account {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Account {
    pub fn new(username: String, password: String, email: Option<String>) -> Self {
        Account {
            username,
            password: shared::pwhash::sha512_crypt::hash(password).unwrap(),
            email,
            created_at: Utc::now(),
        }
    }
}
