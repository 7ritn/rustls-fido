use std::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_repr::*;
use webauthn_rs::prelude::DiscoverableAuthentication;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    PreRegistrationIndication = 0x01,
    PreRegistrationRequest = 0x02,
    RegistrationIndication = 0x03,
    RegistrationRequest = 0x04,
    RegistrationResponse = 0x05,
    AuthenticationIndication = 0x06,
    AuthenticationRequest = 0x07,
    AuthenticationResponse = 0x08
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
/// Mode of operation
pub enum FidoMode {
    /// Requires double handshake
    Registration = 1,
    /// Authentication
    Authentication = 2
}

#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
pub enum FidoPublicKeyAlgorithms {
    #[allow(non_camel_case_types)]
    COSE_ES256 = -7,
    #[allow(non_camel_case_types)]
    COSE_ES384 = -35,
    #[allow(non_camel_case_types)]
    COSE_EDDSA = -8,
    #[allow(non_camel_case_types)]
    COSE_ECDH_ES256 = -25,
    #[allow(non_camel_case_types)]
    COSE_RS256 = -257,
    #[allow(non_camel_case_types)]
    COSE_RS1 = -65535
}

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
/// FidoAuthenticatorAttachment
pub enum FidoAuthenticatorAttachment {
    /// Platform
    Platform = 1,
    /// CrossPlatform
    CrossPlatform = 2,
}

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
/// FidoPolicy
pub enum FidoPolicy {
    /// Required
    Required = 1,
    /// Preferred
    Preferred = 2,
    /// Discouraged
    Discouraged = 3
}

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FidoAuthenticatorTransport {
    USB = 1,
    NFC = 2,
    BLE = 3,
    INTERNAL = 4,
}

#[derive(Debug, Clone)]
pub enum FidoHandshakeState {
    SAS(DiscoverableAuthentication),
    EphemAndUserId((Vec<u8>,Vec<u8>)),
    EphemUserId(Vec<u8>)
}