use password_auth;
use pyo3::prelude::*;

#[derive(FromPyObject)]
enum StrOrBytes {
    Str(String),
    Bytes(Vec<u8>),
}

#[pyfunction]
fn generate_hash(password: StrOrBytes) -> String {
    match password {
        StrOrBytes::Str(s) => password_auth::generate_hash(&s),
        StrOrBytes::Bytes(b) => password_auth::generate_hash(&b),
    }
}

#[pyfunction]
fn verify_password(password: StrOrBytes, hash: String) -> bool {
    let result = match password {
        StrOrBytes::Str(s) => password_auth::verify_password(&s, &hash),
        StrOrBytes::Bytes(b) => password_auth::verify_password(&b, &hash),
    };
    result.is_ok()
}

#[pymodule(gil_used = false)]
fn passuth(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    Ok(())
}
