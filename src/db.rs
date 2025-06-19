use std::{borrow::ToOwned, vec::Vec};
use std::prelude::rust_2024::ToString;
use std::sync::{Arc, Mutex};
use rusqlite::Connection;
use webauthn_rs::prelude::Passkey;
use crate::error::Error;

#[derive(Debug)]
pub(crate) struct User {
    pub(crate) user_id: Vec<u8>,
    pub(crate) passkey: Passkey

}

#[derive(Debug, Clone)]
pub(crate) struct FidoDB {
    pub(crate) conn: Arc<Mutex<Connection>>
}

impl FidoDB {
    pub(crate) fn new(db_path: &str) -> Self {
        let conn = Connection::open(db_path).expect("Could not open database");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                user_id BLOB PRIMARY KEY,
                passkey BLOB NOT NULL UNIQUE
            );",
        ()
        ).expect("Could not create database");

        let conn = Arc::new(Mutex::new(conn));
        Self { conn }
    }

    pub(crate) fn add_user(&self, user: User) -> Result<(), Error> {
        let db = self.conn.lock().unwrap();
        let user_exists = db.query_row(
            "SELECT user_id FROM users WHERE user_id = ?",
            (user.user_id.clone(), ), 
            |_| Ok(())
        ).is_ok();

        if user_exists {
            return Err(Error::General("user exists".to_string()));
        }

        let passkey_blob = serde_cbor::to_vec(&user.passkey).map_err(|_| Error::General("add_user".to_owned()))?;

        db.execute(
            "INSERT INTO users (user_id, passkey) VALUES (?1, ?2)",
            (user.user_id.clone(), passkey_blob)
        ).map_err(|e| Error::General(e.to_string()))?;

        Ok(())
    }

    pub(crate) fn get_passkey(&self, user_id: &Vec<u8>) -> Result<Passkey, Error> {
        let db = self.conn.lock().expect("lock fido db");

        let passkey_blob: Vec<u8> = db.query_row(
            "SELECT passkey FROM users WHERE user_id = ?",
            (user_id,),
            |row| row.get(0)
        ).map_err(|e| Error::General(e.to_string()))?;

        serde_cbor::from_slice(&passkey_blob).map_err(|_| Error::General("get_passkey".to_owned()))
    }
}