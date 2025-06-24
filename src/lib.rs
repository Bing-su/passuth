use fernet;
use password_auth;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

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
    py.allow_threads(|| password_auth::generate_hash(&password))
}

#[pyfunction]
fn verify_password(py: Python<'_>, password: StrOrBytes, hash: String) -> bool {
    py.allow_threads(|| password_auth::verify_password(&password, &hash).is_ok())
}

#[pyclass(module = "passuth.passuth", str)]
#[derive(Clone)]
struct Fernet {
    // Store the key for pickling and unpickling
    key: String,
    fnt: fernet::Fernet,
}

impl std::fmt::Display for Fernet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut secret_str = self.key.chars().take(16).collect::<String>();
        secret_str.push_str("****************");
        write!(f, "Fernet(key={})", secret_str)
    }
}

#[pymethods]
impl Fernet {
    #[new]
    fn new(key: String) -> PyResult<Self> {
        match fernet::Fernet::new(&key) {
            Some(fnt) => Ok(Self { key, fnt }),
            None => Err(PyValueError::new_err("Invalid Fernet key")),
        }
    }

    #[staticmethod]
    fn generate_key() -> String {
        fernet::Fernet::generate_key()
    }

    fn encrypt(&self, data: StrOrBytes) -> String {
        self.fnt.encrypt(data.as_ref())
    }

    fn decrypt(&self, token: String) -> PyResult<Vec<u8>> {
        self.fnt
            .decrypt(&token)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn __getnewargs__(&self) -> (String,) {
        (self.key.clone(),)
    }

    fn __copy__(&self) -> Self {
        self.clone()
    }

    fn __deepcopy__(&self, _memo: Bound<'_, PyAny>) -> Self {
        self.clone()
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }
}

fn get_version() -> PyResult<String> {
    Python::with_gil(|py| {
        let metadata = PyModule::import(py, "importlib.metadata")?;
        let version = metadata.getattr("version")?.call1(("passuth",))?;
        version.extract()
    })
}

#[pymodule(gil_used = false)]
fn passuth(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let version = get_version().unwrap_or_else(|_| "unknown".to_string());
    m.add("__version__", version)?;
    m.add_function(wrap_pyfunction!(generate_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    m.add_class::<Fernet>()?;
    Ok(())
}
