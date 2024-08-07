use pyo3::prelude::*;

#[pyfunction]
fn demangle(s: &str) -> String {
    format!("{}", rustc_demangle::demangle(s))
}

#[pyfunction]
fn demangle_no_hash(s: &str) -> String {
    format!("{:#}", rustc_demangle::demangle(s))
}

#[pyfunction]
fn demangle_msvc(s: &str) -> String {
    use msvc_demangler::DemangleFlags;
    let flags = DemangleFlags::llvm() | DemangleFlags::NAME_ONLY;
    msvc_demangler::demangle(s, flags).unwrap_or(s.to_owned())
}

#[pymodule]
fn rustc_demangle_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(demangle, m)?)?;
    m.add_function(wrap_pyfunction!(demangle_no_hash, m)?)?;
    m.add_function(wrap_pyfunction!(demangle_msvc, m)?)?;
    Ok(())
}
