use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod aesgcm;
mod aesgcmsiv;
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

#[pyclass(
    module = "passuth.passuth",
    name = "Nonce",
    skip_from_py_object,
    frozen,
    eq,
    hash
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PyNonce([u8; 12]);

#[pymethods]
impl PyNonce {
    fn __repr__(&self) -> String {
        format!(
            "Nonce(hex='{}')",
            self.0.map(|b| format!("{b:02x}")).concat()
        )
    }

    fn __bytes__(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<PyNonce> {
        let nonce: [u8; 12] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("Invalid nonce length"))?;
        Ok(PyNonce(nonce))
    }

    fn __copy__(&self) -> Self {
        self.clone()
    }

    #[allow(unused_variables)]
    fn __deepcopy__(&self, memo: Bound<PyAny>) -> Self {
        self.clone()
    }
}

#[pymodule(gil_used = false)]
mod passuth {
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    #[pymodule_export]
    use crate::{PyNonce, generate_hash, verify_password};

    #[pymodule_export]
    use crate::fernet::Fernet;

    #[pymodule_export]
    use crate::aesgcm::{PyAes128Gcm, PyAes256Gcm};

    #[pymodule_export]
    use crate::aesgcmsiv::{PyAes128GcmSiv, PyAes256GcmSiv};
}
