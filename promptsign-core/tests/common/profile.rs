// The root, sub CA and leaf profiles x509-cert 0.2 had built in, with the same
// extensions. x509-cert 0.3 dropped them, and the tests' PKIs depend on their
// exact basic constraints and key usages.

#![allow(dead_code)]

use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{CertificateBuilder, Result};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::Validity;

pub enum Profile {
    Root,
    SubCA {
        issuer: Name,
        path_len_constraint: Option<u8>,
    },
    Leaf {
        issuer: Name,
        enable_key_agreement: bool,
        enable_key_encipherment: bool,
    },
}

pub struct Subject {
    profile: Profile,
    subject: Name,
}

/// `CertificateBuilder::new` with the 0.2 argument order, minus the signer,
/// which 0.3 takes in `build`.
pub fn builder(
    profile: Profile,
    serial: SerialNumber,
    validity: Validity,
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
) -> Result<CertificateBuilder<Subject>> {
    CertificateBuilder::new(Subject { profile, subject }, serial, validity, spki)
}

impl BuilderProfile for Subject {
    fn get_issuer(&self, subject: &Name) -> Name {
        match &self.profile {
            Profile::Root => subject.clone(),
            Profile::SubCA { issuer, .. } | Profile::Leaf { issuer, .. } => issuer.clone(),
        }
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut extensions = vec![SubjectKeyIdentifier::try_from(spk)?.to_extension(subject, &[])?];

        if !matches!(self.profile, Profile::Root) {
            let aki = AuthorityKeyIdentifier::try_from(issuer_spk)?;
            extensions.push(aki.to_extension(subject, &extensions)?);
        }
        let constraints = match &self.profile {
            Profile::Root => BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            Profile::SubCA {
                path_len_constraint,
                ..
            } => BasicConstraints {
                ca: true,
                path_len_constraint: *path_len_constraint,
            },
            Profile::Leaf { .. } => BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        };
        extensions.push(constraints.to_extension(subject, &extensions)?);

        let usage = match &self.profile {
            Profile::Root | Profile::SubCA { .. } => KeyUsages::KeyCertSign | KeyUsages::CRLSign,
            Profile::Leaf {
                enable_key_agreement,
                enable_key_encipherment,
                ..
            } => {
                let mut usage = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
                if *enable_key_encipherment {
                    usage |= KeyUsages::KeyEncipherment;
                }
                if *enable_key_agreement {
                    usage |= KeyUsages::KeyAgreement;
                }
                usage
            }
        };
        extensions.push(KeyUsage(usage).to_extension(subject, &extensions)?);

        Ok(extensions)
    }
}
