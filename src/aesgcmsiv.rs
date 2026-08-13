use aes_gcm_siv::aead::{Aead, Generate, Key, KeyInit};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, Nonce};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::{PyNonce, StrOrBytes};

#[pyclass(module = "passuth.passuth", name = "Aes256GcmSiv")]
pub struct PyAes256GcmSiv {
    aes: Aes256GcmSiv,
}

#[pymethods]
impl PyAes256GcmSiv {
    #[new]
    fn py_new() -> Self {
        let key = Key::<Aes256GcmSiv>::generate();
        let cipher = Aes256GcmSiv::new(&key);
        Self { aes: cipher }
    }

    #[staticmethod]
    fn nonce() -> PyNonce {
        let nonce = Nonce::generate();
        PyNonce(nonce.into())
    }

    fn encrypt(&self, py: Python<'_>, nonce: &PyNonce, plaintext: StrOrBytes) -> PyResult<Vec<u8>> {
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
        "Aes256GcmSiv()"
    }
}

#[pyclass(module = "passuth.passuth", name = "Aes128GcmSiv")]
pub struct PyAes128GcmSiv {
    aes: Aes128GcmSiv,
}

#[pymethods]
impl PyAes128GcmSiv {
    #[new]
    fn py_new() -> Self {
        let key = Key::<Aes128GcmSiv>::generate();
        let cipher = Aes128GcmSiv::new(&key);
        Self { aes: cipher }
    }

    fn nonce(&self) -> PyNonce {
        let nonce = Nonce::generate();
        PyNonce(nonce.into())
    }

    fn encrypt(&self, py: Python<'_>, nonce: &PyNonce, plaintext: StrOrBytes) -> PyResult<Vec<u8>> {
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
        "Aes128GcmSiv()"
    }
}
