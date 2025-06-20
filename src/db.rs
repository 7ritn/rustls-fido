use std::{borrow::ToOwned, vec::Vec};
use std::prelude::rust_2024::ToString;
use std::sync::{Arc, Mutex};
use rusqlite::Connection;
use webauthn_rs::prelude::Passkey;
use crate::error::Error;

#[derive(Debug)]
pub struct RegEntry {
    pub cred_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub passkey: Passkey,
    pub counter: u32,
}

#[derive(Debug, Clone)]
pub struct FidoDB {
    pub conn: Arc<Mutex<Connection>>
}

impl FidoDB {
    pub fn new(db_path: &str) -> Self {
        let conn = Connection::open(db_path).expect("Could not open database");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS passkeys (
                cred_id BLOB PRIMARY KEY,
                user_id BLOB NOT NULL UNIQUE,
                passkey BLOB NOT NULL UNIQUE,
                counter INTEGER NOT NULL
            );",
        ()
        ).expect("Could not create database");

        let conn = Arc::new(Mutex::new(conn));
        Self { conn }
    }

    pub fn add_passkey(&self, reg_entry: RegEntry) -> Result<(), Error> {
        let db = self.conn.lock().unwrap();
        let user_exists = db.query_row(
            "SELECT cred_id FROM passkeys WHERE cred_id = ?1",
            (reg_entry.cred_id.clone(), ),
            |_| Ok(())
        ).is_ok();

        if user_exists {
            return Err(Error::General("user exists".to_string()));
        }

        let passkey_blob = serde_cbor::to_vec(&reg_entry.passkey).map_err(|_| Error::General("add_user".to_owned()))?;

        db.execute(
            "INSERT INTO passkeys (cred_id, user_id, passkey, counter) VALUES (?1, ?, ?3, ?4)",
            (reg_entry.cred_id.clone(), reg_entry.user_id.clone(), passkey_blob, reg_entry.counter)
        ).map_err(|e| Error::General(e.to_string()))?;

        Ok(())
    }

    pub fn get_passkey(&self, user_id: &Vec<u8>) -> Result<Passkey, Error> {
        let db = self.conn.lock().expect("lock fido db");

        let passkey_blob: Vec<u8> = db.query_row(
            "SELECT passkey FROM passkeys WHERE user_id = ?",
            (user_id,),
            |row| row.get(0)
        ).map_err(|e| Error::General(e.to_string()))?;

        serde_cbor::from_slice(&passkey_blob).map_err(|_| Error::General("get_passkey".to_owned()))
    }

    pub fn get_sign_count(&self, user_id: &Vec<u8>) -> Result<u32, Error> {
        let db = self.conn.lock().expect("lock fido db");

        db.query_row(
            "SELECT counter FROM passkeys WHERE user_id = ?",
            (user_id,),
            |row| row.get(0)
        ).map_err(|e| Error::General(e.to_string()))
    }

    pub fn set_sign_count(&self, user_id: &Vec<u8>, sign_count: u32) -> Result<(), Error> {
        let db = self.conn.lock().expect("lock fido db");

        db.execute(
            "UPDATE passkeys SET counter = ?1 WHERE user_id = ?2",
            (sign_count, user_id)
        ).map_err(|e| Error::General(e.to_string()))?;

        Ok(())
    }
}