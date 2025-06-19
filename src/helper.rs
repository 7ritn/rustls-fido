use std::prelude::rust_2024::String;
use pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

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