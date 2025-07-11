use std::prelude::rust_2024::String;
use aws_lc_rs::aead;
use aws_lc_rs::aead::{LessSafeKey, Nonce, UnboundKey};
use pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use crate::error::Error;

pub fn validate_server_name(server_name: &str, server_cert_der: Option<&CertificateDer<'_>>, rp_id: Option<&String>) -> Option<bool> {
    if let Some(rp_id) = rp_id {
        if server_name == rp_id { return Some(true) }
    }

    let server_cert = X509Certificate::from_der(server_cert_der?).ok()?.1;
    Some(server_cert
        .subject_alternative_name()
        .ok()
        .flatten()?
        .value
        .general_names
        .iter()
        .any(|gn| matches!(gn, GeneralName::DNSName(dns) if *dns == server_name)))
}
pub fn encrypt_in_place(key: &Vec<u8>, in_out: &mut Vec<u8>) -> Result<(), Error>{
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|e| Error::General(e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    // 12 bytes = standard GCM nonce size
    let nonce_bytes = *b"012345678901";
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), in_out)
        .map_err(|e| Error::General(e.to_string()))
}


pub fn decrypt_in_place<'in_out>(key: &[u8], in_out: &'in_out mut Vec<u8>) -> Result<&'in_out mut [u8], Error> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|e| Error::General("Could not load key: ".to_string() + &*e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_bytes = *b"012345678901";
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.open_in_place(nonce, aead::Aad::empty(),in_out)
        .map_err(|e| Error::General("Could not decrypt: ".to_string() + &*e.to_string()))
}