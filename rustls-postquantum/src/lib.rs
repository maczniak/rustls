use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::CryptoProvider;

pub fn provider() -> CryptoProvider {
    let parent = default_provider();
    let mut kx_groups = vec![];
    kx_groups.extend(parent.kx_groups);

    CryptoProvider {
        kx_groups,
        ..parent
    }
}
