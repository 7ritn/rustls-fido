use aws_lc_rs::digest;
use std::sync::{Arc, Mutex};
use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use log::{debug, info};
use authenticator::ctap2::server::{AuthenticationExtensionsClientInputs, PublicKeyCredentialUserEntity, RelyingParty};
use base64::engine::general_purpose;
use aws_lc_rs::digest::digest;
use authenticator::{Pin, StatusUpdate};
use std::sync::mpsc::channel;
use authenticator::statecallback::StateCallback;
use base64::Engine;
use crate::enums::{FidoMode, FidoPolicy};
use crate::error::Error;
use crate::helper::decrypt_in_place;
use crate::messages::{FidoAuthenticationRequest, FidoAuthenticationResponse, FidoClientData, FidoPreRegistrationResponse, FidoRegistrationRequest, FidoRegistrationResponse, FidoResponse};

/// FidoClient
#[derive(Debug, Clone)]
pub struct FidoClient {
    pub(crate) mode: FidoMode,
    pub(crate) user_name: Option<String>,
    pub(crate) user_display_name: Option<String>,
    pub(crate) ticket: Option<Vec<u8>>,
    pub(crate) fido_device_pin: String,
    pub(crate) persistent_reg_state: Option<Arc<Mutex<Option<RegistrationState>>>>,
    pub(crate) response_buffer: Arc<Mutex<Option<FidoResponse>>>,
}

/// state to be remembered between handshakes
#[derive(Debug, Clone)]
pub struct RegistrationState {
    /// ephem_user_id
    pub ephem_user_id: Vec<u8>,
    /// ephem encryption key
    pub gcm_key: Vec<u8>
}

impl FidoClient {
    /// Create a new fido client
    pub fn new(
        mode: FidoMode,
        user_name: Option<String>,
        user_display_name: Option<String>,
        ticket: Option<Vec<u8>>,
        fido_device_pin: String
    ) -> Self {
        let mut persistent_reg_state = None;
        if mode == FidoMode::Registration {
            if user_name.is_none() || user_display_name.is_none() || ticket.is_none() {
                panic!("missing required user_name, user_display_name or ticket");
            }
            persistent_reg_state = Some(Default::default());
        }
        Self {
            mode,
            user_name,
            user_display_name,
            ticket,
            fido_device_pin,
            persistent_reg_state,
            response_buffer: Default::default(),
        }
    }

    pub fn pre_register_fido(&self, ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) {
        let reg_option = self.persistent_reg_state.as_ref().unwrap();
        let mut reg_state = reg_option.lock().expect("lock persistent_reg_state");
        *reg_state = Some(RegistrationState{ephem_user_id, gcm_key});

        let mut response = self.response_buffer.lock().expect("lock response_buffer");
        *response = Some(FidoResponse::PreRegistration(FidoPreRegistrationResponse::new(
            self.user_name.clone().unwrap(),
            self.user_display_name.clone().unwrap(),
            self.ticket.as_ref().expect("no ticket").clone(),
        )));
    }

    pub fn register_fido(&self, request: FidoRegistrationRequest) -> Result<(), Error> {
        let mut manager = AuthenticatorService::new().expect("AuthenticatorService::new");
        manager.add_u2f_usb_hid_platform_transports();

        debug!("Prepare register FIDO token");

        let gcm_key = self.persistent_reg_state
            .as_ref()
            .unwrap()
            .lock()
            .expect("lock persistent_reg_state")
            .take()
            .ok_or(Error::General("no pre_reg_state available".to_string()))?
            .gcm_key;

        // ToDo verify request and actual user info match
        let mut enc_user_id = request.enc_user_id.clone();
        let user_id = decrypt_in_place(&gcm_key, &mut enc_user_id)?;
        let user = PublicKeyCredentialUserEntity {
            id: user_id.into(),
            name: Some(self.user_name.clone().unwrap()),
            display_name: Some(self.user_display_name.clone().unwrap()),
        };

        let origin = "https://".to_string() + &*request.rp_id;
        let challenge_b64 = general_purpose::STANDARD.encode(&request.challenge);

        let client_data = FidoClientData{
            mode: "webauthn.create".to_string(),
            challenge: challenge_b64,
            origin: origin.clone(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data).expect("serialize client_data_json");
        let binding = digest(&digest::SHA256, client_data_json.as_bytes());
        let client_data_hash = binding.as_ref().try_into().expect("digest client_data_json");

        let authenticator_selection = request.optionals.authenticator_selection.clone().unwrap_or_default();
        let excluded_credentials = request.optionals.excluded_credentials.clone().unwrap_or_default();

        let ctap_args = RegisterArgs {
            client_data_hash,
            relying_party: RelyingParty {
                id: request.rp_id,
                name: Some(request.rp_name),
            },
            origin,
            user,
            pub_cred_params: request.pubkey_cred_params.iter().map(|alg| alg.clone().try_into().expect("convert pubkey_cred_params")).collect(),
            exclude_list: excluded_credentials.iter().map(|cred| cred.clone().into()).collect(),
            user_verification_req: authenticator_selection.user_verification.into(),
            resident_key_req: authenticator_selection.resident_key.into(),
            extensions: AuthenticationExtensionsClientInputs {
                ..Default::default()
            },
            pin: Some(Pin::new(&self.fido_device_pin)),
            use_ctap1_fallback: false,
        };

        debug!("Start registering FIDO token");

        let (register_tx, register_rx) = channel();
        let (status_tx, _status_rx) = channel::<StatusUpdate>();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).expect("register_tx send");
        }));

        manager.register(request.optionals.timeout.unwrap_or(10000).into(), ctap_args, status_tx, callback)
            .map_err(|e| Error::General(e.to_string()))?;

        info!("Authenticate now!");

        let register_result = register_rx
            .recv()
            .map_err(|e| Error::General(e.to_string()))?
            .map_err(|e| Error::General(e.to_string()))?;

        let mut response = self.response_buffer.lock().unwrap();
        *response = Some(FidoResponse::Registration(FidoRegistrationResponse::new(
            serde_cbor::to_vec(&register_result.att_obj).expect("serialize register_result"),
            client_data_json
        )));

        Ok(())
    }

    pub fn authenticate_fido(&self, request: FidoAuthenticationRequest) -> Result<(), Error> {
        let mut manager = AuthenticatorService::new().map_err(|e| Error::General(e.to_string()))?;
        manager.add_u2f_usb_hid_platform_transports();

        // Discovering creds:
        let allow_list = Vec::new();
        let rp_id = request.optionals.rpid.ok_or(Error::General("missing required rp_id".into()))?;
        let origin = "https://".to_string() + &*rp_id.clone();
        let challenge_b64 = general_purpose::STANDARD.encode(&request.challenge);

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
            user_verification_req: request.optionals.user_verification.unwrap_or(FidoPolicy::Preferred).into(),
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
            .sign(request.optionals.timeout.unwrap_or(10000) as u64, ctap_args, status_tx, callback)
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

        let mut response = self.response_buffer.lock().unwrap();
        *response = Some(FidoResponse::Authentication(FidoAuthenticationResponse::new(
            client_data_json,
            sign_result.assertion.auth_data.to_vec(),
            sign_result.assertion.signature,
            user_handle.expect("user_handle"),
            selected_credential_id.expect("selected_credential_id")
        )));

        Ok(())
    }

    pub fn ticket(&self) -> Option<&Vec<u8>> {
        self.ticket.as_ref()
    }

    pub fn mode(&self) -> FidoMode {
        self.mode
    }

    pub fn current_reg_state(&self) -> Option<RegistrationState> {
        let Some(reg_lock) = self.persistent_reg_state.as_ref() else { return None };
        let binding = reg_lock.lock().expect("lock persistent_reg_state");
        binding.clone()
    }

    pub fn take_response_buffer(&self) -> Option<FidoResponse> {
        let mut binding = self.response_buffer.lock().expect("lock response_buffer");
        binding.take()
    }
}