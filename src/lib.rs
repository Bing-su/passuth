use pyo3::prelude::*;

mod aesgcm;
mod fernet;

#[derive(FromPyObject)]
enum StrOrBytes {
    Str(String),
    Bytes(Vec<u8>),
}

impl AsRef<[u8]> for StrOrBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            StrOrBytes::Str(s) => s.as_bytes(),
            StrOrBytes::Bytes(b) => b,
        }
    }
}

#[pyfunction]
fn generate_hash(py: Python<'_>, password: StrOrBytes) -> String {
    py.detach(|| password_auth::generate_hash(&password))
}

#[pyfunction]
fn verify_password(py: Python<'_>, password: StrOrBytes, hash: &str) -> bool {
    py.detach(|| password_auth::verify_password(&password, hash).is_ok())
}

#[pymodule(gil_used = false)]
mod passuth {
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    #[pymodule_export]
    use crate::{generate_hash, verify_password};

    #[pymodule_export]
    use crate::fernet::Fernet;

    #[pymodule_export]
    use crate::aesgcm::{PyAes128Gcm, PyAes128GcmSiv, PyAes256Gcm, PyAes256GcmSiv, PyNonce};
}
