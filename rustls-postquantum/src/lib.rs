use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use aws_lc_rs::kem;

pub fn provider() -> CryptoProvider {
    let parent = default_provider();
    let mut kx_groups = vec![&X25519Kyber768Draft00 as &dyn SupportedKxGroup];
    kx_groups.extend(parent.kx_groups);

    CryptoProvider {
        kx_groups,
        ..parent
    }
}

///
#[derive(Debug)]
pub struct X25519Kyber768Draft00;

impl SupportedKxGroup for X25519Kyber768Draft00 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let x25519 = kx_group::X25519.start()?;

        let kyber = kem::KemPrivateKey::generate(&kem::KYBER768_R3)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let kyber_pub = kyber
            .compute_public_key()
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let mut combined_pub_key = Vec::with_capacity(COMBINED_PUBKEY_LEN);
        combined_pub_key.extend_from_slice(x25519.pub_key());
        combined_pub_key.extend_from_slice(kyber_pub.as_ref());

        let encoded_priv_key = kyber.as_ref().to_vec();

        Ok(Box::new(Active {
            x25519,
            encoded_priv_key,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != COMBINED_PUBKEY_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let x25519 = kx_group::X25519.start_and_complete(&client_share[..X25519_LEN])?;
        let mut combined_secret = [0u8; 64];
        combined_secret[..X25519_LEN].copy_from_slice(x25519.secret.secret_bytes());
        let mut combined_share = [0u8; COMBINED_CIPHERTEXT_LEN];
        combined_share[..X25519_LEN].copy_from_slice(&x25519.pub_key);

        let kyber_pub = kem::KemPublicKey::new(&kem::KYBER768_R3, &client_share[X25519_LEN..])
            .map_err(|_| INVALID_KEY_SHARE)?;

        kyber_pub.encapsulate(INVALID_KEY_SHARE, |ct, ss| {
            combined_secret[X25519_LEN..].copy_from_slice(ss);
            combined_share[X25519_LEN..].copy_from_slice(ct);
            Ok(())
        })?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: combined_share.to_vec(),
            secret: SharedSecret::from(&combined_secret[..]),
        })
    }

    fn name(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

struct Active {
    x25519: Box<dyn ActiveKeyExchange>,
    /// XXX: serialisation is needed because kem::KemPrivateKey is not Send/Sync
    encoded_priv_key: Vec<u8>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != COMBINED_CIPHERTEXT_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let x25519_ss = self
            .x25519
            .complete(&peer_pub_key[..X25519_LEN])?;

        let mut result = [0u8; COMBINED_SHARED_SECRET_LEN];
        result[..X25519_LEN].copy_from_slice(x25519_ss.secret_bytes());

        let kyber = kem::KemPrivateKey::new(&kem::KYBER768_R3, &self.encoded_priv_key)
            .map_err(|_| INVALID_KEY_SHARE)?;

        let mut ciphertext = [0u8; KYBER_CIPHERTEXT_LEN];
        ciphertext.clone_from_slice(&peer_pub_key[X25519_LEN..]);

        kyber.decapsulate(&mut ciphertext, INVALID_KEY_SHARE, |ss| {
            result[X25519_LEN..].copy_from_slice(ss);
            Ok(())
        })?;

        Ok(SharedSecret::from(&result[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

const NAMED_GROUP: NamedGroup = NamedGroup::Unknown(0x6399);

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const KYBER_CIPHERTEXT_LEN: usize = 1088;
const COMBINED_PUBKEY_LEN: usize = X25519_LEN + 1184;
const COMBINED_CIPHERTEXT_LEN: usize = X25519_LEN + KYBER_CIPHERTEXT_LEN;
const COMBINED_SHARED_SECRET_LEN: usize = X25519_LEN + 32;
