use aes_gcm::aead::{Aead, Generate, Key, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::StrOrBytes;

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
    fn generate() -> PyNonce {
        Self(aes_gcm_siv::Nonce::generate().into())
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

macro_rules! aes_class {
    ($py:ident, $cipher:ty, $name:literal) => {
        #[pyclass(module = "passuth.passuth", name = $name, skip_from_py_object, frozen)]
        #[derive(Clone)]
        pub struct $py {
            aes: $cipher,
        }

        #[pymethods]
        impl $py {
            #[new]
            fn py_new() -> Self {
                Self {
                    aes: <$cipher>::new(&Key::<$cipher>::generate()),
                }
            }

            #[staticmethod]
            fn nonce() -> PyNonce {
                PyNonce::generate()
            }

            fn encrypt(
                &self,
                py: Python<'_>,
                nonce: &PyNonce,
                plaintext: StrOrBytes,
            ) -> PyResult<Vec<u8>> {
                py.detach(|| {
                    self.aes
                        .encrypt(&nonce.0.into(), plaintext.as_ref())
                        .map_err(|e| PyValueError::new_err(e.to_string()))
                })
            }

            fn decrypt(
                &self,
                py: Python<'_>,
                nonce: &PyNonce,
                ciphertext: StrOrBytes,
            ) -> PyResult<Vec<u8>> {
                py.detach(|| {
                    self.aes
                        .decrypt(&nonce.0.into(), ciphertext.as_ref())
                        .map_err(|e| PyValueError::new_err(e.to_string()))
                })
            }

            fn __repr__(&self) -> &str {
                concat!($name, "()")
            }

            fn __copy__(&self) -> Self {
                self.clone()
            }

            #[allow(unused_variables)]
            fn __deepcopy__(&self, memo: Bound<PyAny>) -> Self {
                self.clone()
            }
        }
    };
}

aes_class!(PyAes256Gcm, Aes256Gcm, "Aes256Gcm");
aes_class!(PyAes128Gcm, Aes128Gcm, "Aes128Gcm");
aes_class!(PyAes128GcmSiv, Aes128GcmSiv, "Aes128GcmSiv");
aes_class!(PyAes256GcmSiv, Aes256GcmSiv, "Aes256GcmSiv");
