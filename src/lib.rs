use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyType;

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

#[pyclass(module = "passuth.passuth", str, skip_from_py_object)]
#[derive(Clone)]
struct Fernet {
    // Store the key for pickling and unpickling
    key: String,
    fnt: fernet::Fernet,
}

impl std::fmt::Display for Fernet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut secret_str = self.key.chars().take(8).collect::<String>();
        secret_str.push_str("*".repeat(24).as_str());
        write!(f, "Fernet(key={})", secret_str)
    }
}

#[pymethods]
impl Fernet {
    #[new]
    fn py_new(key: String) -> PyResult<Self> {
        match fernet::Fernet::new(&key) {
            Some(fnt) => Ok(Self { key, fnt }),
            None => Err(PyValueError::new_err("Invalid Fernet key")),
        }
    }

    #[classmethod]
    fn new(_cls: Bound<'_, PyType>) -> Self {
        let key = Self::generate_key();
        Self {
            key: key.clone(),
            fnt: fernet::Fernet::new(&key).expect("Always valid key"),
        }
    }

    #[staticmethod]
    fn generate_key() -> String {
        fernet::Fernet::generate_key()
    }

    fn encrypt(&self, py: Python<'_>, data: StrOrBytes) -> String {
        py.detach(|| self.fnt.encrypt(data.as_ref()))
    }

    fn decrypt(&self, py: Python<'_>, token: String) -> PyResult<Vec<u8>> {
        py.detach(|| {
            self.fnt
                .decrypt(&token)
                .map_err(|e| PyValueError::new_err(e.to_string()))
        })
    }

    fn __getnewargs__(&self) -> (String,) {
        (self.key.clone(),)
    }

    fn __copy__(&self) -> Self {
        self.clone()
    }

    #[allow(unused_variables)]
    fn __deepcopy__(&self, memo: Bound<'_, PyAny>) -> Self {
        self.clone()
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }
}

#[pymodule(gil_used = false)]
mod passuth {
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    #[pymodule_export]
    use super::{Fernet, generate_hash, verify_password};
}
