use std::io;
use std::sync::mpsc::channel;
use std::time::Duration;
use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs};
use authenticator::ctap2::server::{AuthenticationExtensionsClientInputs, PublicKeyCredentialUserEntity, RelyingParty};
use authenticator::{Pin, StatusUpdate};
use authenticator::statecallback::StateCallback;
use aws_lc_rs::digest;
use aws_lc_rs::digest::digest;
use base64::Engine;
use base64::engine::general_purpose;
use config::Config;
use log::{debug, info};
use webauthn_rs::prelude::{Base64UrlSafeData, Credential, PasskeyRegistration, Url, Uuid};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{AuthenticatorAttestationResponseRaw, RegisterPublicKeyCredential};
use x509_parser::nom::AsBytes;
use rustls_fido::db::{FidoDB, RegEntry};
use rustls_fido::enums::FidoPublicKeyAlgorithms;
use rustls_fido::enums::FidoPublicKeyAlgorithms::COSE_ES256;
use rustls_fido::error::Error;
use rustls_fido::messages::{FidoClientData, FidoCredential, FidoRegistrationAuthenticatorSelection, FidoRegistrationResponse};

struct RegisterState {
    user_id: Uuid,
    user_name: String,
    user_display_name: String,
    rp_id: String,
    rp_name: String,
    challenge: Vec<u8>,
    fido_device_pin: String,
    timeout: u64,
    authenticator_selection: FidoRegistrationAuthenticatorSelection,
    pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>,
    excluded_credentials: Vec<FidoCredential>,
    webauthn: Webauthn,
    db: FidoDB
}

impl RegisterState {
    fn register_fido_client(&self) -> Result<FidoRegistrationResponse, Error> {
        let mut manager = AuthenticatorService::new().expect("AuthenticatorService::new");
        manager.add_u2f_usb_hid_platform_transports();

        debug!("Preparing to register FIDO token");

        let user = PublicKeyCredentialUserEntity {
            id: self.user_id.into(),
            name: Some(self.user_name.clone()),
            display_name: Some(self.user_display_name.clone()),
        };

        let origin = "https://".to_string() + self.rp_id.as_str();
        let challenge_b64 = general_purpose::STANDARD.encode(&self.challenge);

        let client_data = FidoClientData{
            mode: "webauthn.create".to_string(),
            challenge: challenge_b64,
            origin: origin.clone(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data).expect("serialize client_data_json");
        let binding = digest(&digest::SHA256, client_data_json.as_bytes());
        let client_data_hash = binding.as_ref().try_into().expect("digest client_data_json");

        let authenticator_selection = self.authenticator_selection.clone();
        let excluded_credentials = self.excluded_credentials.clone();

        let ctap_args = RegisterArgs {
            client_data_hash,
            relying_party: RelyingParty {
                id: self.rp_id.clone(),
                name: Some(self.rp_name.clone()),
            },
            origin,
            user,
            pub_cred_params: self.pubkey_cred_params.iter().map(|alg| alg.clone().try_into().expect("convert pubkey_cred_params")).collect(),
            exclude_list: excluded_credentials.iter().map(|cred| cred.clone().into()).collect(),
            user_verification_req: authenticator_selection.user_verification.into(),
            resident_key_req: authenticator_selection.resident_key.into(),
            extensions: AuthenticationExtensionsClientInputs {
                ..Default::default()
            },
            pin: Some(Pin::new(&self.fido_device_pin)),
            use_ctap1_fallback: false,
        };

        debug!("Starting registration of FIDO token on device");

        let (register_tx, register_rx) = channel();
        let (status_tx, _status_rx) = channel::<StatusUpdate>();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).expect("register_tx send");
        }));

        manager.register(self.timeout.into(), ctap_args, status_tx, callback)
            .map_err(|e| Error::General(e.to_string()))?;

        info!("Authenticate now!");

        let register_result = register_rx
            .recv()
            .map_err(|e| Error::General(e.to_string()))?
            .map_err(|e| Error::General(e.to_string()))?;
        
        debug!("Device registration successful");

        Ok(FidoRegistrationResponse::new(
            serde_cbor::to_vec(&register_result.att_obj).expect("serialize register_result"),
            client_data_json
        ))
    }

    fn start_register_fido_server(&mut self) -> Result<PasskeyRegistration, Error> {
        debug!("Starting registration of FIDO token on server");
        let (ccr, skr) = self.webauthn
            .start_passkey_registration(
                self.user_id,
                &self.user_name,
                &self.user_display_name,
                None
            )
            .map_err(|e| Error::General(e.to_string()))?;

        self.challenge = ccr.public_key.challenge.to_vec();

        Ok(skr)
    }

    pub fn finish_register_fido_server(&mut self, skr: PasskeyRegistration, reg: FidoRegistrationResponse) -> Result<(), Error> {
        let attestation_response = AuthenticatorAttestationResponseRaw{
            attestation_object: reg.attestation_object.as_bytes().into(),
            client_data_json: reg.client_data_json.as_bytes().into(),
            transports: None
        };

        let reg = RegisterPublicKeyCredential{
            id: String::new(),
            raw_id: Base64UrlSafeData::new(),
            response: attestation_response,
            type_: String::new(),
            extensions: Default::default()
        };

        debug!("Finishing registration of FIDO token on server");
        let passkey = self.webauthn.finish_passkey_registration(&reg, &skr)
            .map_err(|e| Error::General(e.to_string()))?;
        let cred: Credential = passkey.clone().into();
        
        let reg_entry = RegEntry {cred_id: passkey.cred_id().to_vec(), user_id: self.user_id.into(), passkey, counter: cred.counter};
        
        self.db.add_passkey(reg_entry)?;
        debug!("Added FIDO token to database");
        Ok(())
    }

    pub fn register_fido(&mut self) -> Result<(), Error> {
        let skr = self.start_register_fido_server()?;
        let reg_response = self.register_fido_client()?;
        self.finish_register_fido_server(skr, reg_response)?;
        Ok(())
    }
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::builder().filter_level(log::LevelFilter::Debug).filter(Some("authenticator"), log::LevelFilter::Warn).init();

    let settings = Config::builder()
        .add_source(config::File::with_name("config/config.toml"))
        .build()?;

    let rp_id = settings.get_string("rp_id")?;
    let rp_name = settings.get_string("rp_name")?;
    let user_name = settings.get_string("user_name")?;
    let user_display_name = settings.get_string("user_display_name")?;
    let timeout = settings.get_int("timeout")? as u64;
    let fido_device_pin = settings.get_string("fido_device_pin").unwrap_or_else(|_| {
        let stdin = io::stdin();
        let input = &mut String::new();
        print!("Enter FIDO device PIN: ");
        stdin.read_line(input).expect("read_line");
        input.clone()
    });
    let db_path = settings.get_string("db_path")?;
    
    let rp_origin = Url::parse(&format!("https://{}", rp_id))?;
    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
        .rp_name(&rp_name)
        .timeout(Duration::new(timeout, 0))
        .build()?;
    let db = FidoDB::new(&db_path);

    let mut state = RegisterState{
        user_id: Uuid::new_v4(),
        user_name,
        user_display_name,
        rp_id,
        rp_name,
        fido_device_pin,
        timeout,
        webauthn,
        db,
        pubkey_cred_params: vec![COSE_ES256],
        challenge: Default::default(),
        authenticator_selection: Default::default(),
        excluded_credentials: Default::default()
    };

    state.register_fido()?;

    Ok(())
}