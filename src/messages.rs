use core::fmt;
use std::{format, string::String, vec::Vec};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::enums::{FidoAuthenticatorAttachment, FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms, MessageType};

/// FidoPreRegistrationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoPreIndication {
    /// message_type
    pub message_type: u8,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoPreRequest {
    pub message_type: u8,
    #[serde(with = "serde_bytes")]
    pub ephem_user_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub gcm_key: Vec<u8>
}

/// FidoRegistrationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoRegistrationIndication {
    /// message_type
    pub message_type: u8,
    /// ephem_user_id
    #[serde(with = "serde_bytes")]
    pub ephem_user_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_user_name: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_user_display_name: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_ticket: Vec<u8>
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoRegistrationRequest {
    pub message_type: u8,
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    #[serde(with = "serde_bytes")]
    pub enc_user_name: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_user_display_name: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_user_id: Vec<u8>,
    pub pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>,
    pub optionals: FidoRegistrationRequestOptionals
}

#[derive(Debug, Clone, Default)]
pub struct FidoRegistrationRequestOptionals {
    pub timeout: Option<u32>,
    pub authenticator_selection: Option<FidoRegistrationAuthenticatorSelection>,
    pub excluded_credentials: Option<Vec<FidoCredential>>
}


impl Serialize for FidoRegistrationRequestOptionals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(timeout) = &self.timeout {
            map.serialize_entry(&1, timeout)?;
        }
        if let Some(ref val) = self.authenticator_selection {
            map.serialize_entry(&2, &val)?;
        }
        if let Some(ref val) = self.excluded_credentials {
            map.serialize_entry(&3, &val)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for FidoRegistrationRequestOptionals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = FidoRegistrationRequestOptionals;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a CBOR map with integer keys 1 through 5")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut timeout = None;
                let mut authenticator_selection = FidoRegistrationAuthenticatorSelection::default();
                let mut excluded_credentials = None;

                while let Some(key) = map.next_key::<u8>()? {
                    match key {
                        1 => timeout = map.next_value()?,
                        2 => authenticator_selection = map.next_value()?,
                        3 => excluded_credentials = map.next_value()?,
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?; // skip unknown keys
                        }
                    }
                }
                let a = FidoRegistrationRequestOptionals {
                    timeout,
                    authenticator_selection: Some(authenticator_selection),
                    excluded_credentials
                };

                Ok(a)
            }
        }

        deserializer.deserialize_map(FieldVisitor)
    }
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoRegistrationAuthenticatorSelection {
    pub attachment: FidoAuthenticatorAttachment,
    pub resident_key: FidoPolicy,
    pub user_verification: FidoPolicy
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoRegistrationResponse {
    pub message_type: u8,
    #[serde(with = "serde_bytes")]
    pub attestation_object: Vec<u8>,
    pub client_data_json: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub  struct FidoClientData {
    #[serde(rename = "type")]
    pub mode: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool

}

/// FidoAuthenticationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationIndication {
    /// message_type
    pub message_type: u8
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationRequest {
    pub message_type: u8,
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    pub optionals: FidoAuthenticationRequestOptionals
}

#[derive(Debug, Clone, Default)]
pub struct FidoAuthenticationRequestOptionals {
    pub timeout: Option<u32>,
    pub rpid: Option<String>,
    pub user_verification: Option<FidoPolicy>,
    pub allow_credentials: Option<Vec<FidoCredential>>,
    pub extensions: Option<Vec<FidoExtension>>
}
impl Serialize for FidoAuthenticationRequestOptionals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(timeout) = &self.timeout { map.serialize_entry(&1, timeout)? }
        if let Some(rpid) = &self.rpid { map.serialize_entry(&2, rpid)? }
        if let Some(user_verification) = &self.user_verification { map.serialize_entry(&3, user_verification)? }
        if let Some(allow_credentials) = &self.allow_credentials { map.serialize_entry(&4, allow_credentials)? }
        if let Some(extensions) = &self.extensions { map.serialize_entry(&5, extensions)? }
        map.end()
    }
}

impl<'de> Deserialize<'de> for FidoAuthenticationRequestOptionals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = FidoAuthenticationRequestOptionals;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with integer keys 1..=5")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut timeout = None;
                let mut rpid = None;
                let mut user_verification = None;
                let mut allow_credentials = None;
                let mut extensions = None;

                while let Some(key) = map.next_key::<u8>()? {
                    match key {
                        1 => timeout = map.next_value()?,
                        2 => rpid = map.next_value()?,
                        3 => user_verification = map.next_value()?,
                        4 => allow_credentials = map.next_value()?,
                        5 => extensions = map.next_value()?,
                        _ => { let _ : de::IgnoredAny = map.next_value()?; }
                    }
                }

                let a = FidoAuthenticationRequestOptionals {
                    timeout,
                    rpid,
                    user_verification,
                    allow_credentials,
                    extensions,
                };

                Ok(a)
            }
        }

        deserializer.deserialize_map(FieldVisitor)
    }
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoCredential {
    pub credential_type: u8,
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    pub transports: FidoAuthenticatorTransport,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoExtension {
    pub extension_id: String,
    #[serde(with = "serde_bytes")]
    pub extension_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationResponse {
    pub message_type: u8,
    pub client_data_json: String,
    #[serde(with = "serde_bytes")]
    pub authenticator_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub optionals: FidoAuthenticationResponseOptionals,
}

#[derive(Debug, Clone, Default)]
pub struct FidoAuthenticationResponseOptionals {
    pub user_handle: Option<Vec<u8>>,
    pub selected_credential_id: Option<Vec<u8>>
}

impl Serialize for FidoAuthenticationResponseOptionals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(user_handle) = &self.user_handle { map.serialize_entry(&1, user_handle)? }
        if let Some(selected_credential_id) = &self.selected_credential_id { map.serialize_entry(&2, selected_credential_id)? }
        map.end()
    }
}

impl<'de> Deserialize<'de> for FidoAuthenticationResponseOptionals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = FidoAuthenticationResponseOptionals;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with integer keys 1..=5")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut user_handle = None;
                let mut selected_credential_id = None;

                while let Some(key) = map.next_key::<u8>()? {
                    match key {
                        1 => user_handle = map.next_value()?,
                        2 => selected_credential_id = map.next_value()?,
                        _ => { let _ : de::IgnoredAny = map.next_value()?; }
                    }
                }

                let a = FidoAuthenticationResponseOptionals {
                    user_handle,
                    selected_credential_id,
                };

                Ok(a)
            }
        }

        deserializer.deserialize_map(FieldVisitor)
    }
}

// Group Enums

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FidoIndication {
    PreRegistration(FidoPreIndication),
    Registration(FidoRegistrationIndication),
    Authentication(FidoAuthenticationIndication)
}

impl<'de> Deserialize<'de> for FidoIndication {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        struct FidoMessageVisitor;

        impl<'de> Visitor<'de> for FidoMessageVisitor {
            type Value = FidoIndication;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence starting with a message type (u8)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let message_type: u8 = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match message_type {
                    1 => Ok(FidoIndication::PreRegistration(FidoPreIndication {
                        message_type
                    })),
                    3 => {
                        // For Registration, we need the ephem_user_id
                        let ephem_user_id_bytes: &[u8] = seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let ephem_user_id = Vec::from(ephem_user_id_bytes);

                        let enc_user_name_bytes: &[u8] = seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        let enc_user_display_name_bytes: &[u8] = seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                        let enc_ticket_bytes: &[u8] = seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(4, &self))?;


                        Ok(FidoIndication::Registration(FidoRegistrationIndication {
                            message_type,
                            ephem_user_id,
                            enc_user_name: enc_user_name_bytes.to_vec(),
                            enc_user_display_name: enc_user_display_name_bytes.to_vec(),
                            enc_ticket: enc_ticket_bytes.to_vec(),
                        }))
                    },
                    6 => Ok(FidoIndication::Authentication(FidoAuthenticationIndication {
                        message_type
                    })),
                    _ => Err(de::Error::custom(format!(
                        "unknown message type: {}",
                        message_type
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(FidoMessageVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FidoRequest {
    PreRegistration(FidoPreRequest),
    Registration(FidoRegistrationRequest),
    Authentication(FidoAuthenticationRequest)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FidoResponse {
    Registration(FidoRegistrationResponse),
    Authentication(FidoAuthenticationResponse)
}

// Implement Constructors

impl FidoPreIndication {
    pub fn new() -> Self {
        Self { 
            message_type: MessageType::PreRegistrationIndication as u8,
        }
    }
}

impl FidoPreRequest {
    pub fn new(ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::PreRegistrationRequest as u8,
            ephem_user_id,
            gcm_key
        }
    }
}

impl FidoRegistrationIndication {
    pub fn new(ephem_user_id: &[u8], enc_user_name: &[u8], enc_user_display_name: &[u8], enc_ticket: &[u8]) -> Self {
        Self { 
            message_type: MessageType::RegistrationIndication as u8,
            ephem_user_id: ephem_user_id.to_vec(),
            enc_user_name: enc_user_name.to_vec(),
            enc_user_display_name: enc_user_display_name.to_vec(),
            enc_ticket: enc_ticket.to_vec(),
        }
    }
}

impl FidoRegistrationRequest {
    pub fn new(
        challenge: Vec<u8>, 
        rp_id: String, 
        rp_name: String, 
        user_name: Vec<u8>, 
        user_display_name: Vec<u8>, 
        user_id: Vec<u8>, 
        pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>, 
        options: Option<FidoRegistrationRequestOptionals>
    ) -> Self {
        Self { 
            message_type: MessageType::RegistrationRequest as u8,
            challenge,
            rp_id,
            rp_name,
            enc_user_name: user_name,
            enc_user_display_name: user_display_name,
            enc_user_id: user_id,
            pubkey_cred_params,
            optionals: options.unwrap_or_default()
        }
    }
}
impl Default for FidoRegistrationAuthenticatorSelection {
    fn default() -> Self {
        Self {
            attachment: FidoAuthenticatorAttachment::CrossPlatform,
            resident_key: FidoPolicy::Required,
            user_verification: FidoPolicy::Preferred,
        }
    }
}

impl FidoRegistrationResponse {
    pub fn new(attestation_object: Vec<u8>, client_data_json: String) -> Self {
        Self { 
            message_type: MessageType::RegistrationResponse as u8,
            attestation_object,
            client_data_json
        }
    }
}

impl FidoAuthenticationIndication {
    pub fn new() -> Self {
        Self { 
            message_type: MessageType::AuthenticationIndication as u8
        }
    }
}

impl FidoAuthenticationRequest {
    pub fn new(challenge: Vec<u8>, options: Option<FidoAuthenticationRequestOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationRequest as u8,
            challenge,
            optionals: options.unwrap_or_default()
        }
    }
}

impl FidoAuthenticationResponse {
    pub fn new(client_data_json: String, authenticator_data: Vec<u8>, signature: Vec<u8>, user_handle: Option<Vec<u8>>, selected_credential_id: Option<Vec<u8>>) -> Self {
        let optionals = FidoAuthenticationResponseOptionals {
            user_handle,
            selected_credential_id,
        };

        Self {
            message_type: MessageType::AuthenticationResponse as u8,
            client_data_json,
            authenticator_data,
            signature,
            optionals
        }
    }
}