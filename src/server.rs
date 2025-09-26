use std::{borrow::ToOwned, collections::HashMap, format, string::String, vec, vec::Vec};
use std::prelude::rust_2024::ToString;
use core::time::Duration;
use log::debug;
use webauthn_rs::prelude::{Base64UrlSafeData, Credential, DiscoverableAuthentication, PasskeyRegistration, Url, Uuid};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential};
use x509_parser::nom::AsBytes;
use crate::enums::{FidoAuthenticatorAttachment, FidoPolicy};
use crate::error::Error;
use crate::helper::encrypt_in_place;
use crate::messages::{FidoCredential, FidoPreRegistrationRequest, FidoRegistrationAuthenticatorSelection, FidoRegistrationRequestOptionals};
use super::{db::{FidoDB, RegEntry}, enums::FidoPublicKeyAlgorithms, messages::{FidoAuthenticationRequest, FidoAuthenticationRequestOptionals, FidoAuthenticationResponse, FidoRegistrationRequest}};

type EphemUserId = Vec<u8>;
type UserId = Vec<u8>;

/// State and configuration for Fido TLS Extension server-side
#[derive(Debug, Clone)]
pub struct FidoServer {
    pub webauthn: Webauthn,
    pub(crate) db: FidoDB,
    pub(crate) user_verification: FidoPolicy,
    pub(crate) resident_key: FidoPolicy,
    pub(crate) authenticator_attachment: FidoAuthenticatorAttachment,
    pub(crate) timeout: u32,
    pub(crate) ticket: Vec<u8>,
    pub(crate) mandatory: bool,
    pub(crate) registration_state: HashMap<EphemUserId, ((FidoRegistrationRequest, UserId), PasskeyRegistration)>,
    pub(crate) pre_registration_state: HashMap<Vec<u8>, Vec<u8>>
}

impl FidoServer {
    /// Create a new configuration for Fido TLS Extension server-side
    pub  fn new(
        rp_id: String,
        rp_name: String,
        user_verification: FidoPolicy,
        resident_key: FidoPolicy,
        authenticator_attachment: FidoAuthenticatorAttachment,
        timeout: u32,
        ticket: Vec<u8>,
        mandatory: bool,
        db_path: &str
    ) -> Self {
        let rp_origin = Url::parse(&format!("https://{}", rp_id.clone()))
            .expect("Invalid DN");
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Invalid configuration")
            .rp_name(&rp_name)
            .timeout(Duration::new(timeout as u64, 0))
            .build()
            .expect("Couldn't build FIDO verifier");
        let db = FidoDB::new(db_path);
        
        debug!("FIDO server extension configured");
        debug!("\tRP ID: {}", rp_id);
        debug!("\tRP Name: {}", rp_name);
        debug!("\tUser Verification Policy: {:?}", user_verification);
        debug!("\tResident Key Policy: {:?}", resident_key);
        debug!("\tAuthenticator Attachment Policy: {:?}", authenticator_attachment);
        debug!("\tToken Timeout Policy: {}", timeout);
        debug!("\tTicket: {:?}", ticket);
        debug!("\tFIDO Authentication Mandatory: {}", mandatory);
        debug!("\tPath to Database: {}", db_path);

        Self{
            webauthn,
            db,
            user_verification,
            resident_key,
            authenticator_attachment,
            timeout,
            ticket,
            mandatory,
            registration_state: Default::default(),
            pre_registration_state: Default::default()
        }
    }
    pub fn start_register_fido(&mut self, ephem_user_id: Vec<u8>, ticket: Vec<u8>, user_name: String, user_display_name: String) -> Result<(), Error>{
        if self.ticket != ticket {
            return Err(Error::General("fido registration ticket invalid".to_string()))
        }

        let gcm_key = self.pre_registration_state
            .get(&ephem_user_id)
            .ok_or(Error::General("client did not pre-register".to_string()))?;
                
        let user_id = Uuid::new_v4();

        debug!("Creating Registration Challenge {:?}", user_id);
        debug!("\tEphem User ID: {:?},\nUser ID: {:?},\nUser Name: {},\nUser Display Name: {}", ephem_user_id, user_id, user_name, user_display_name);

        let (ccr, skr) = self.webauthn
            .start_passkey_registration(
                user_id,
                &user_name,
                &user_display_name,
                None
            )
            .map_err(|e| Error::General(e.to_string()))?;
            
        let mut enc_user_name = user_name.clone().as_bytes().to_vec();
        let mut enc_user_display_name = user_display_name.clone().as_bytes().to_vec();
        let mut enc_user_id = user_id.clone().as_bytes().to_vec();

        let authenticator_selection = FidoRegistrationAuthenticatorSelection{
            attachment: self.authenticator_attachment.clone(),
            resident_key: self.resident_key.clone(),
            user_verification: self.user_verification.clone()
        };
        let excluded_credentials: Vec<FidoCredential> = vec![];

        encrypt_in_place(gcm_key, &mut enc_user_name)?;
        encrypt_in_place(gcm_key, &mut enc_user_display_name)?;
        encrypt_in_place(gcm_key, &mut enc_user_id)?;

        let optionals = FidoRegistrationRequestOptionals{
            timeout: Some(self.timeout),
            authenticator_selection: Some(authenticator_selection),
            excluded_credentials: Some(excluded_credentials),
        };

        let registration_request = FidoRegistrationRequest::new(
            ccr.public_key.challenge.to_vec(),
            ccr.public_key.rp.id,
            ccr.public_key.rp.name,
            enc_user_name,
            enc_user_display_name,
            enc_user_id,
            std::vec![FidoPublicKeyAlgorithms::COSE_ES256],
            Some(optionals)
        );

        self.registration_state.insert(ephem_user_id.clone(), ((registration_request, user_id.as_bytes().into()), skr));

        Ok(())
    }

    pub fn finish_register_fido(&mut self, ephem_user_id: Vec<u8>, user_id: Vec<u8>, client_data_json: String, attestation_object: Vec<u8>) -> Result<(), Error> {
        let (_, skr) = self.registration_state.remove(&ephem_user_id).ok_or(Error::General("no registration state found".to_string()))?;

        debug!("Verifying Authentication Response");
        debug!("\tEphem User ID: {:?},\nUser ID: {:?}", ephem_user_id, user_id);

        let attestation_response = AuthenticatorAttestationResponseRaw{
            attestation_object: attestation_object.as_bytes().into(),
            client_data_json: client_data_json.as_bytes().into(),
            transports: None
        };

        let reg = RegisterPublicKeyCredential{
            id: String::new(),
            raw_id: Base64UrlSafeData::new(),
            response: attestation_response,
            type_: String::new(),
            extensions: Default::default()
        };
        let passkey = self.webauthn.finish_passkey_registration(&reg, &skr).map_err(|e| Error::General(e.to_string()))?;
        let cred: Credential = passkey.clone().into();
        let reg_entry = RegEntry {cred_id: passkey.cred_id().to_vec(), user_id, passkey, counter: cred.counter};
        self.db.add_passkey(reg_entry)?;

        debug!("FIDO registration successful");

        Ok(())
    }

    pub fn start_authentication_fido(&self) -> Result<(FidoAuthenticationRequest, DiscoverableAuthentication), Error> {
        debug!("Creating Authentication Challenge");

        let (ar, sas) = self.webauthn.start_discoverable_authentication().map_err(|e| Error::General(e.to_string()))?;

        let authentication_request = FidoAuthenticationRequest::new(
            ar.public_key.challenge.to_vec(),
            Some(FidoAuthenticationRequestOptionals{
                timeout: ar.public_key.timeout,
                rpid: Some(ar.public_key.rp_id),
                ..Default::default()
            })
        );

        Ok((authentication_request, sas))
    }

    pub fn finish_authentication_fido(&self, fido_response: FidoAuthenticationResponse, sas: DiscoverableAuthentication) -> Result<(), Error>{
        debug!("Verifying Authentication Response");
        let credential_id_string = String::from_utf8(fido_response.selected_credential_id.clone()).unwrap_or_default();

        let authentication_response = AuthenticatorAssertionResponseRaw{
            authenticator_data: fido_response.authenticator_data.into(),
            client_data_json: fido_response.client_data_json.as_bytes().to_vec().into(),
            signature: fido_response.signature.into(),
            user_handle: Some(fido_response.user_handle.into())
        };

        let reg = PublicKeyCredential { 
            id: credential_id_string,
            raw_id: fido_response.selected_credential_id.into(),
            response: authentication_response, 
            type_: String::new(),
            extensions: Default::default()
        };

        let (uuid, _) = self.webauthn.identify_discoverable_authentication(&reg).map_err(|e| Error::General(e.to_string()))?;

        let user_id = uuid.clone().as_bytes().to_vec();
        let passkey = self.db.get_passkey(&user_id)?;

        debug!("Response associated with User ID {}", Uuid::from_bytes(user_id.clone().try_into().unwrap()));

        let _authentication_result = self.webauthn.finish_discoverable_authentication(&reg, sas, &[passkey.into()]).map_err(|e| Error::General(e.to_string()))?;

        let cred_counter = self.db.get_sign_count(&user_id)?;
        let auth_counter = _authentication_result.counter() as u32;
        if cred_counter != 0 || auth_counter != 0 {
            if cred_counter >= auth_counter {
                return Err(Error::General("counter mismatch".to_string()))
            }
        }
        self.db.set_sign_count(&user_id, auth_counter)?;

        debug!("FIDO authentication successful");

        Ok(())
    }

    pub fn add_ephem_user(&mut self, ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) ->  FidoPreRegistrationRequest {
        self.pre_registration_state.insert(ephem_user_id.clone(), gcm_key.clone());
        FidoPreRegistrationRequest::new(ephem_user_id, gcm_key)
    }

    pub fn get_registration_request(&mut self, ephem_user_id: &Vec<u8>) ->  Result<&(FidoRegistrationRequest, Vec<u8>), Error> {
        if let Some(state) = self.registration_state.get(ephem_user_id){
            Ok(&state.0)
        } else {
            Err(Error::General("No pre reg request has been made".to_owned()))
        }
    }

    pub fn is_mandatory(&self) -> bool {
        self.mandatory
    }
}
