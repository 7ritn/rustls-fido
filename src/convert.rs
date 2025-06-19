use std::vec;
use authenticator::ctap2::server::{PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, ResidentKeyRequirement, Transport, UserVerificationRequirement};
use crate::enums::{FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms};
use crate::messages::FidoCredential;

use std::convert::TryFrom;
use authenticator::crypto::COSEAlgorithm;

#[derive(Debug)]
pub enum ConversionError {
    UnsupportedAlgorithm(u8),
}

impl TryFrom<FidoPublicKeyAlgorithms> for PublicKeyCredentialParameters {
    type Error = ConversionError;

    fn try_from(value: FidoPublicKeyAlgorithms) -> Result<Self, Self::Error> {
        let alg = match value {
            FidoPublicKeyAlgorithms::COSE_ES256 => COSEAlgorithm::ES256,
            FidoPublicKeyAlgorithms::COSE_ES384 => COSEAlgorithm::ES384,
            FidoPublicKeyAlgorithms::COSE_EDDSA => COSEAlgorithm::EDDSA,
            FidoPublicKeyAlgorithms::COSE_ECDH_ES256 => COSEAlgorithm::ECDH_ES_HKDF256,
            FidoPublicKeyAlgorithms::COSE_RS256 => COSEAlgorithm::RS256,
            FidoPublicKeyAlgorithms::COSE_RS1 => COSEAlgorithm::INSECURE_RS1,
        };

        Ok(PublicKeyCredentialParameters { alg })
    }
}
impl From<FidoAuthenticatorTransport> for Transport {
    fn from(value: FidoAuthenticatorTransport) -> Self {
        match value {
            FidoAuthenticatorTransport::USB => Transport::USB,
            FidoAuthenticatorTransport::NFC => Transport::NFC,
            FidoAuthenticatorTransport::BLE => Transport::BLE,
            FidoAuthenticatorTransport::INTERNAL => Transport::Internal,
        }
    }
}

impl From<FidoCredential> for PublicKeyCredentialDescriptor {
    fn from(value: FidoCredential) -> Self {
        PublicKeyCredentialDescriptor {
            id: value.credential_id,
            transports: vec![value.transports.into()],
        }
    }
}

impl From<FidoPolicy> for ResidentKeyRequirement {
    fn from(value: FidoPolicy) -> Self {
        match value {
            FidoPolicy::Required => ResidentKeyRequirement::Required,
            FidoPolicy::Preferred => ResidentKeyRequirement::Preferred,
            FidoPolicy::Discouraged => ResidentKeyRequirement::Discouraged,
        }
    }
}

impl From<FidoPolicy> for UserVerificationRequirement {
    fn from(value: FidoPolicy) -> Self {
        match value {
            FidoPolicy::Required => UserVerificationRequirement::Required,
            FidoPolicy::Preferred => UserVerificationRequirement::Preferred,
            FidoPolicy::Discouraged => UserVerificationRequirement::Discouraged,
        }
    }
}