use aes_gcm::aead::{Aead, Generate, Key, KeyInit};
use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::StrOrBytes;

#[pyclass(module = "passuth.passuth", name = "Nonce")]
pub struct PyNonce(Nonce<U12>);

#[pymethods]
impl PyNonce {
    fn __repr__(&self) -> String {
        "Nonce()".into()
    }
}

#[pyclass(module = "passuth.passuth", name = "Aes256Gcm")]
pub struct PyAes256Gcm {
    aes: Aes256Gcm,
}

#[pymethods]
impl PyAes256Gcm {
    #[new]
    fn py_new() -> Self {
        let key = Key::<Aes256Gcm>::generate();
        let cipher = Aes256Gcm::new(&key);
        Self { aes: cipher }
    }

    #[staticmethod]
    fn nonce() -> PyNonce {
        let nonce = Nonce::<U12>::generate();
        PyNonce(nonce)
    }

    fn encrypt(&self, py: Python<'_>, nonce: &PyNonce, plaintext: StrOrBytes) -> PyResult<Vec<u8>> {
        py.detach(|| {
            self.aes
                .encrypt(&nonce.0, plaintext.as_ref())
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
                .decrypt(&nonce.0, ciphertext.as_ref())
                .map_err(|e| PyValueError::new_err(e.to_string()))
        })
    }

    fn __repr__(&self) -> String {
        "Aes256Gcm()".into()
    }
}

#[pyclass(module = "passuth.passuth", name = "Aes128Gcm")]
pub struct PyAes128Gcm {
    aes: Aes128Gcm,
}

#[pymethods]
impl PyAes128Gcm {
    #[new]
    fn py_new() -> Self {
        let key = Key::<Aes128Gcm>::generate();
        let cipher = Aes128Gcm::new(&key);
        Self { aes: cipher }
    }

    fn nonce(&self) -> PyNonce {
        let nonce = Nonce::<U12>::generate();
        PyNonce(nonce)
    }

    fn encrypt(&self, py: Python<'_>, nonce: &PyNonce, plaintext: StrOrBytes) -> PyResult<Vec<u8>> {
        py.detach(|| {
            self.aes
                .encrypt(&nonce.0, plaintext.as_ref())
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
                .decrypt(&nonce.0, ciphertext.as_ref())
                .map_err(|e| PyValueError::new_err(e.to_string()))
        })
    }

    fn __repr__(&self) -> String {
        "Aes128Gcm()".into()
    }
}
