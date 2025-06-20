use std::io::Stderr;
use std::sync::mpsc::channel;
use std::time::Duration;
use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
use authenticator::{Pin, StatusUpdate};
use authenticator::statecallback::StateCallback;
use aws_lc_rs::digest;
use aws_lc_rs::digest::digest;
use base64::Engine;
use base64::engine::general_purpose;
use config::Config;
use log::{debug, info};
use webauthn_rs::prelude::{DiscoverableAuthentication, Url};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{AuthenticatorAssertionResponseRaw, PublicKeyCredential};
use rustls_fido::db::FidoDB;
use rustls_fido::error::Error;
use rustls_fido::messages::{FidoAuthenticationResponse, FidoClientData, FidoRegistrationAuthenticatorSelection};

struct AuthenticationState {
    rp_id: String,
    challenge: Vec<u8>,
    fido_device_pin: String,
    timeout: u64,
    authenticator_selection: FidoRegistrationAuthenticatorSelection,
    webauthn: Webauthn,
    db: FidoDB
}

impl AuthenticationState {
    fn authenticate_fido_client(&self) -> Result<FidoAuthenticationResponse, Error> {
        let mut manager = AuthenticatorService::new().map_err(|e| Error::General(e.to_string()))?;
        manager.add_u2f_usb_hid_platform_transports();

        // Discovering creds:
        let allow_list = Vec::new();
        let rp_id = self.rp_id.clone();
        let origin = "https://".to_string() + &*rp_id.clone();
        let challenge_b64 = general_purpose::STANDARD.encode(&self.challenge);

        let client_data = FidoClientData{
            mode: "webauthn.get".to_string(),
            challenge: challenge_b64,
            origin: origin.clone(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data).expect("serialize client_data");
        let binding = digest(&digest::SHA256, client_data_json.as_bytes());
        let client_data_hash = binding.as_ref().try_into().expect("digest client_data_json");

        let (status_tx, _status_rx) = channel::<StatusUpdate>();

        let ctap_args = SignArgs {
            client_data_hash,
            origin,
            relying_party_id: rp_id,
            allow_list,
            user_verification_req: self.authenticator_selection.user_verification.clone().into(),
            user_presence_req: true,
            extensions: Default::default(),
            pin: Some(Pin::new(&self.fido_device_pin)),
            use_ctap1_fallback: false,
        };

        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).expect("failed to send sign");
        }));

        manager
            .sign(self.timeout, ctap_args, status_tx, callback)
            .map_err(|e| Error::General(format!("{:?}", e)))?;

        info!("fido: Authenticate now!");

        let sign_result = sign_rx
            .recv()
            .map_err(|e| Error::General(format!("{:?}", e)))?
            .map_err(|e| Error::General(format!("{:?}", e)))?;

        let user_handle = match sign_result.assertion.user {
            Some(user) => Some(user.id),
            None => None
        };

        let selected_credential_id = match sign_result.assertion.credentials {
            Some(cred) => Some(cred.id),
            None => None
        };

        Ok(FidoAuthenticationResponse::new(
            client_data_json,
            sign_result.assertion.auth_data.to_vec(),
            sign_result.assertion.signature,
            user_handle.expect("user_handle"),
            selected_credential_id.expect("selected_credential_id")
        ))
    }

    fn start_authenticate_fido_server(&mut self) -> Result<DiscoverableAuthentication, Error> {
        debug!("Start registering FIDO token on server");
        let (ar, sas) = self.webauthn
            .start_discoverable_authentication()
            .map_err(|e| Error::General(e.to_string()))?;


        self.challenge = ar.public_key.challenge.to_vec();

        Ok(sas)
    }

    //noinspection ALL
    pub fn finish_register_fido_server(&mut self, sas: DiscoverableAuthentication, aut: FidoAuthenticationResponse) -> Result<(), Error> {
        let credential_id_string = String::from_utf8(aut.selected_credential_id.clone()).unwrap_or_default();

        let authentication_response = AuthenticatorAssertionResponseRaw{
            authenticator_data: aut.authenticator_data.into(),
            client_data_json: aut.client_data_json.as_bytes().to_vec().into(),
            signature: aut.signature.into(),
            user_handle: Some(aut.user_handle.into())
        };

        let reg = PublicKeyCredential {
            id: credential_id_string,
            raw_id: aut.selected_credential_id.into(),
            response: authentication_response,
            type_: String::new(),
            extensions: Default::default()
        };

        let (uuid, _) = self.webauthn.identify_discoverable_authentication(&reg).map_err(|e| Error::General(e.to_string()))?;

        let user_id = uuid.clone().as_bytes().to_vec();
        let passkey = self.db.get_passkey(&user_id)?;
        let _authentication_result = self.webauthn.finish_discoverable_authentication(&reg, sas, &[passkey.into()]).map_err(|e| Error::General(e.to_string()))?;

        let cred_counter = self.db.get_sign_count(&user_id)?;
        let auth_counter = _authentication_result.counter() as u32;
        if cred_counter != 0 || auth_counter != 0 {
            if cred_counter >= auth_counter {
                return Err(Error::General("counter mismatch".to_string()))
            }
        }

        Ok(())
    }

    pub fn authenticate_fido(&mut self) -> Result<(), Error> {
        let sas = self.start_authenticate_fido_server()?;
        let aut = self.authenticate_fido_client()?;
        self.finish_register_fido_server(sas, aut)?;
        Ok(())
    }
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let settings = Config::builder()
        .add_source(config::File::with_name("config/config.toml"))
        .build()?;
    
    let rp_id = settings.get_string("rp_id")?;
    let rp_name = settings.get_string("rp_name")?;
    let timeout = settings.get_int("timeout")? as u64;
    let fido_device_pin = settings.get_string("fido_device_pin")?;
    let db_path = settings.get_string("db_path")?;
    
    let rp_origin = Url::parse(&format!("https://{}", rp_id))?;
    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
        .rp_name(&rp_name)
        .timeout(Duration::new(timeout, 0))
        .build()?;
    let db = FidoDB::new(&db_path);

    let mut state = AuthenticationState {
        rp_id,
        fido_device_pin,
        timeout,
        webauthn,
        db,
        authenticator_selection: Default::default(),
        challenge: Default::default()
    };

    state.authenticate_fido()?;

    Ok(())
}