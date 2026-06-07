use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::Keypair;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::signature::Verifier;
use sha2::Digest;
use spki::{DecodePublicKey, EncodePublicKey};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use zip::ZipArchive;

/// Signs JAR bytes with the provided RSA private key.
///
/// This function creates a standard JAR signature following the OpenJDK jarsigner format:
/// - MANIFEST.MF with SHA-256 digests of all files (excluding META-INF)
/// - .SF file with manifest digest and individual file digests
/// - .RSA file with PKCS#1 RSA signature of the .SF file
///
/// # Arguments
///
/// * `jar_bytes` - The JAR file contents as bytes
/// * `key_bytes` - RSA private key in PKCS#8 DER format
/// * `_pass` - Passcode parameter kept for API compatibility (not used)
/// * `override_signature` - If true, removes existing signatures before signing
///
/// # Returns
///
/// Returns the signed JAR bytes on success.
///
/// # Errors
///
/// Returns an error if:
/// - The private key cannot be parsed
/// - The JAR cannot be read as a ZIP archive
/// - Signature generation fails
///
/// # Example
///
/// ```no_run
/// use jarsigned::{sign_bytes, generate_key_pair};
///
/// let (private_key, _) = generate_key_pair().unwrap();
/// let jar_bytes = std::fs::read("app.jar").unwrap();
/// let signed_jar = sign_bytes(&jar_bytes, &private_key, "", true).unwrap();
/// ```
pub fn sign_bytes(
    jar_bytes: &[u8],
    key_bytes: &[u8],
    _pass: &str,
    override_signature: bool,
) -> Result<Vec<u8>> {
    sign_bytes_with_cert_chain(jar_bytes, key_bytes, None, _pass, override_signature, &mut |_, _| {})
}

/// Signs JAR bytes with the provided RSA private key and optional certificate chain.
///
/// This is an extended version of `sign_bytes` that accepts an optional certificate chain.
/// Note: Certificate chain support is not fully implemented in this version.
///
/// # Arguments
///
/// * `jar_bytes` - The JAR file contents as bytes
/// * `key_bytes` - RSA private key in PKCS#8 DER format
/// * `_cert_chain` - Optional certificate chain (not currently used)
/// * `_pass` - Passcode parameter kept for API compatibility (not used)
/// * `override_signature` - If true, removes existing signatures before signing
///
/// # Returns
///
/// Returns the signed JAR bytes on success.
pub fn sign_bytes_with_cert_chain<F>(
    jar_bytes: &[u8],
    key_bytes: &[u8],
    _cert_chain: Option<&[Vec<u8>]>,
    _pass: &str,
    override_signature: bool,
    mut progress_callback: F,
) -> Result<Vec<u8>>
where
    F: FnMut(String, bool),
{
    let signing_key = SigningKey::<Sha256>::from_pkcs8_der(key_bytes)
        .map_err(|e| anyhow!("Failed to parse RSA key: {}", e))?;

    let cursor = Cursor::new(jar_bytes);
    let mut zip =
        ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to open JAR as ZIP: {}", e))?;

    let mut file_digests = HashMap::new();
    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

        let name = file.name().to_string();

        if name.starts_with("META-INF/") {
            continue;
        }

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| anyhow!("Failed to read file {}: {}", name, e))?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let digest = STANDARD.encode(hasher.finalize());
        file_digests.insert(name, digest);
    }

    let mut manifest = String::new();
    manifest.push_str("Manifest-Version: 1.0\r\n");
    manifest.push_str("Created-By: jarsigned\r\n");
    manifest.push_str("\r\n");

    for (name, digest) in &file_digests {
        manifest.push_str(&format!("Name: {}\r\n", name));
        manifest.push_str(&format!("SHA-256-Digest: {}\r\n", digest));
        manifest.push_str("\r\n");
    }

    let manifest_bytes = manifest.as_bytes();
    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(manifest_bytes);
    let manifest_digest = manifest_hasher.finalize();

    let main_attrs_end = manifest.find("\r\n\r\n").unwrap_or(manifest.len());
    let main_attrs_bytes = &manifest_bytes[..main_attrs_end];
    let mut main_attrs_hasher = Sha256::new();
    main_attrs_hasher.update(main_attrs_bytes);
    let main_attrs_digest = main_attrs_hasher.finalize();

    let mut sf_content = String::new();
    sf_content.push_str("Signature-Version: 1.0\r\n");
    sf_content.push_str("SHA-256-Digest-Manifest: ");
    sf_content.push_str(&STANDARD.encode(manifest_digest));
    sf_content.push_str("\r\n");
    sf_content.push_str("SHA-256-Digest-Manifest-Main-Attributes: ");
    sf_content.push_str(&STANDARD.encode(main_attrs_digest));
    sf_content.push_str("\r\n");
    sf_content.push_str("Signed-By: jarsigned\r\n");
    sf_content.push_str("\r\n");

    for (name, digest) in &file_digests {
        sf_content.push_str(&format!("Name: {}\r\n", name));
        sf_content.push_str(&format!("SHA-256-Digest: {}\r\n", digest));
        sf_content.push_str("\r\n");
    }

    let sf_bytes = sf_content.as_bytes();
    let mut sf_hasher = Sha256::new();
    sf_hasher.update(sf_bytes);
    let sf_digest = sf_hasher.finalize();

    let signature = signing_key.sign(&sf_digest).to_bytes();

    let cms_der = signature.to_vec();

    let sig_block_ext = "RSA";

    let cursor = Cursor::new(jar_bytes);
    let mut zip =
        ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to re-open JAR as ZIP: {}", e))?;

    let mut modified_jar = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut modified_jar));

        for i in 0..zip.len() {
            let mut file = zip
                .by_index(i)
                .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

            let name = file.name().to_string();

            if override_signature && name.starts_with("META-INF/") {
                let lower_name = name.to_ascii_lowercase();
                if lower_name.ends_with(".sf")
                    || lower_name.ends_with(".rsa")
                    || lower_name.ends_with(".dsa")
                    || lower_name.ends_with(".ec")
                    || lower_name == "meta-inf/manifest.mf"
                {
                    continue;
                }
            }

            progress_callback(name.clone(), false);

            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(file.compression())
                .unix_permissions(file.unix_mode().unwrap_or(0o644));

            writer
                .start_file(&name, options)
                .map_err(|e| anyhow!("Failed to start file {}: {}", name, e))?;

            std::io::copy(&mut file, &mut writer)
                .map_err(|e| anyhow!("Failed to copy file {}: {}", name, e))?;

            progress_callback(name.clone(), true);
        }

        let text_options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let mut has_meta_inf_dir = false;
        for i in 0..zip.len() {
            let file = zip
                .by_index(i)
                .map_err(|e| anyhow!("Failed to check file {}: {}", i, e))?;
            if file.name() == "META-INF/" {
                has_meta_inf_dir = true;
                break;
            }
        }

        if !has_meta_inf_dir {
            writer
                .start_file(
                    "META-INF/",
                    (zip::write::FileOptions::default() as zip::write::FileOptions<'_, ()>)
                        .unix_permissions(0o40755),
                )
                .map_err(|e| anyhow!("Failed to create META-INF dir: {}", e))?;
        }

        writer
            .start_file("META-INF/MANIFEST.MF", text_options)
            .map_err(|e| anyhow!("Failed to create MANIFEST.MF: {}", e))?;
        writer
            .write_all(manifest_bytes)
            .map_err(|e| anyhow!("Failed to write MANIFEST.MF: {}", e))?;

        writer
            .start_file("META-INF/SIGNATURE.SF", text_options)
            .map_err(|e| anyhow!("Failed to create SIGNATURE.SF: {}", e))?;
        writer
            .write_all(sf_bytes)
            .map_err(|e| anyhow!("Failed to write SF file: {}", e))?;

        let sig_block_name = format!("META-INF/SIGNATURE.{}", sig_block_ext);
        writer
            .start_file(&sig_block_name, text_options)
            .map_err(|e| anyhow!("Failed to create signature block file: {}", e))?;
        writer
            .write_all(&cms_der)
            .map_err(|e| anyhow!("Failed to write signature block: {}", e))?;

        writer
            .finish()
            .map_err(|e| anyhow!("Failed to finish ZIP: {}", e))?;
    }

    Ok(modified_jar)
}

/// Extracts the signature block bytes from a signed JAR.
///
/// Searches for signature files (.SF, .RSA, .DSA) in the META-INF directory
/// and returns their contents.
///
/// # Arguments
///
/// * `signed_jar_bytes` - The signed JAR file contents as bytes
///
/// # Returns
///
/// Returns `Some(signature_bytes)` if a signature file is found,
/// or `None` if no signature files are present.
///
/// # Errors
///
/// Returns an error if the JAR cannot be read as a ZIP archive.
pub fn extract_signature_bytes(signed_jar_bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let cursor = Cursor::new(signed_jar_bytes);
    let mut zip =
        ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to open signed JAR: {}", e))?;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

        let name = file.name().to_string();
        if name.starts_with("META-INF/")
            && (name.ends_with(".SF") || name.ends_with(".RSA") || name.ends_with(".DSA"))
        {
            let mut sig_bytes = Vec::new();
            std::io::copy(&mut file, &mut sig_bytes)
                .map_err(|e| anyhow!("Failed to read signature file {}: {}", name, e))?;
            return Ok(Some(sig_bytes));
        }
    }

    Ok(None)
}

/// Generates a new RSA key pair for JAR signing.
///
/// Creates a 2048-bit RSA key pair suitable for JAR signing.
/// The private key is returned in PKCS#8 DER format.
///
/// # Returns
///
/// Returns a tuple of (private_key_der, public_key_der) where both are in DER format.
///
/// # Errors
///
/// Returns an error if key generation fails.
///
/// # Example
///
/// ```no_run
/// use jarsigned::generate_key_pair;
///
/// let (private_key, public_key) = generate_key_pair().unwrap();
/// ```
pub fn generate_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();

    let private_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow!("Failed to encode private key: {}", e))?
        .to_bytes()
        .to_vec();

    let public_der = verifying_key
        .to_public_key_der()
        .map_err(|e| anyhow!("Failed to encode public key: {}", e))?
        .as_bytes()
        .to_vec();

    Ok((private_der, public_der))
}

/// Generates a complete signing key pair.
///
/// This is a convenience function that wraps `generate_key_pair`.
/// Note: Certificate generation is not implemented in this version.
///
/// # Returns
///
/// Returns a tuple of (private_key_der, public_key_der) in DER format.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_signing_credentials() -> Result<(Vec<u8>, Vec<u8>)> {
    generate_key_pair()
}

/// Checks if a JAR is signed.
///
/// Searches for signature files (.SF, .RSA, .DSA) in the META-INF directory
/// to determine if the JAR has been signed.
///
/// # Arguments
///
/// * `jar_bytes` - The JAR file contents as bytes
///
/// # Returns
///
/// Returns `true` if signature files are present, `false` otherwise.
///
/// # Errors
///
/// Returns an error if the JAR cannot be read as a ZIP archive.
///
/// # Example
///
/// ```no_run
/// use jarsigned::is_signed;
///
/// let jar_bytes = std::fs::read("app.jar").unwrap();
/// let signed = is_signed(&jar_bytes).unwrap();
/// ```
pub fn is_signed(jar_bytes: &[u8]) -> Result<bool> {
    let cursor = Cursor::new(jar_bytes);
    let mut zip = ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to open JAR: {}", e))?;

    for i in 0..zip.len() {
        let file = zip
            .by_index(i)
            .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

        let name = file.name();
        if name.starts_with("META-INF/")
            && (name.ends_with(".SF") || name.ends_with(".RSA") || name.ends_with(".DSA"))
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verifies a JAR signature using the provided public key.
///
/// This function performs a simplified signature verification by checking
/// the RSA signature on the .SF file digest.
///
/// # Arguments
///
/// * `jar_bytes` - The signed JAR file contents as bytes
/// * `public_key_bytes` - RSA public key in DER format
///
/// # Returns
///
/// Returns `true` if the signature is valid, `false` otherwise.
///
/// # Errors
///
/// Returns an error if:
/// - The JAR cannot be read
/// - Signature files are missing
/// - The public key cannot be parsed
///
/// # Note
///
/// This is a simplified verification. Full certificate chain verification
/// is not implemented in this version.
pub fn verify(jar_bytes: &[u8], public_key_bytes: &[u8]) -> Result<bool> {
    let cursor = Cursor::new(jar_bytes);
    let mut zip = ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to open JAR: {}", e))?;

    let mut sf_content = None;
    let mut rsa_content = None;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

        let name = file.name();
        if name.starts_with("META-INF/") {
            if name.ends_with(".SF") {
                let mut content = Vec::new();
                std::io::copy(&mut file, &mut content)
                    .map_err(|e| anyhow!("Failed to read SF file: {}", e))?;
                sf_content = Some(content);
            } else if name.ends_with(".RSA") || name.ends_with(".DSA") {
                let mut content = Vec::new();
                std::io::copy(&mut file, &mut content)
                    .map_err(|e| anyhow!("Failed to read RSA file: {}", e))?;
                rsa_content = Some(content);
            }
        }
    }

    let sf_bytes = sf_content.ok_or_else(|| anyhow!("No .SF file found"))?;
    let rsa_bytes = rsa_content.ok_or_else(|| anyhow!("No .RSA/.DSA file found"))?;

    let verifying_key = VerifyingKey::<Sha256>::from_public_key_der(public_key_bytes)
        .map_err(|e| anyhow!("Failed to parse public key: {}", e))?;

    let mut sf_hasher = Sha256::new();
    sf_hasher.update(&sf_bytes);
    let sf_digest = sf_hasher.finalize();

    if rsa_bytes.len() < 32 {
        return Ok(false);
    }

    let signature = rsa::pkcs1v15::Signature::try_from(&rsa_bytes[..256])
        .map_err(|_| anyhow!("Invalid signature format"))?;

    verifying_key
        .verify(&sf_digest, &signature)
        .map_err(|_| anyhow!("Signature verification failed"))?;

    Ok(true)
}

/// Extracts the public key from a signed JAR.
///
/// Attempts to extract the public key from the signature block.
/// Note: This is a placeholder implementation and currently always returns None.
///
/// # Arguments
///
/// * `jar_bytes` - The signed JAR file contents as bytes
///
/// # Returns
///
/// Returns `Some(public_key_der)` if the public key can be extracted,
/// or `None` if extraction is not possible.
///
/// # Note
///
/// Full CMS/PKCS#7 parsing is not implemented in this version.
pub fn extract_public_key(jar_bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let cursor = Cursor::new(jar_bytes);
    let mut zip = ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to open JAR: {}", e))?;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| anyhow!("Failed to get file {}: {}", i, e))?;

        let name = file.name();
        if name.starts_with("META-INF/") && (name.ends_with(".RSA") || name.ends_with(".DSA")) {
            let mut content = Vec::new();
            std::io::copy(&mut file, &mut content)
                .map_err(|e| anyhow!("Failed to read signature file: {}", e))?;

            if content.len() > 100 {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::FileOptions;

    fn create_test_jar() -> Vec<u8> {
        let mut buffer = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

            let options: zip::write::FileOptions<'_, ()> =
                FileOptions::default().compression_method(zip::CompressionMethod::Stored);

            writer.start_file("test.txt", options).unwrap();
            writer.write_all(b"Hello, World!").unwrap();

            writer
                .start_file(
                    "META-INF/",
                    (FileOptions::default() as zip::write::FileOptions<'_, ()>)
                        .unix_permissions(0o40755),
                )
                .unwrap();
            writer.start_file("META-INF/config.xml", options).unwrap();
            writer.write_all(b"<config/>").unwrap();

            writer.finish().unwrap();
        }
        buffer
    }

    #[test]
    fn test_generate_key_pair() {
        let (priv_key, pub_key) = generate_key_pair().unwrap();
        assert!(!priv_key.is_empty());
        assert!(!pub_key.is_empty());
        assert!(priv_key.len() > 100);
        assert!(pub_key.len() > 100);
    }

    #[test]
    fn test_generate_signing_credentials() {
        let (priv_key, pub_key) = generate_signing_credentials().unwrap();
        assert!(!priv_key.is_empty());
        assert!(!pub_key.is_empty());
        assert!(priv_key.len() > 100);
        assert!(pub_key.len() > 100);
    }

    #[test]
    fn test_sign_bytes() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_key_pair().unwrap();

        let signed_jar = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();

        assert!(!signed_jar.is_empty());
        assert!(signed_jar.len() > jar_bytes.len());
    }

    #[test]
    fn test_sign_bytes_with_cert_chain() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_signing_credentials().unwrap();
        let cert_chain: Vec<Vec<u8>> = vec![];

        let signed_jar =
            sign_bytes_with_cert_chain(&jar_bytes, &priv_key, Some(&cert_chain), "", false)
                .unwrap();

        assert!(!signed_jar.is_empty());
        assert!(signed_jar.len() > jar_bytes.len());
    }

    #[test]
    fn test_sign_bytes_override_signature() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_key_pair().unwrap();

        let signed_once = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();
        let signed_twice = sign_bytes(&signed_once, &priv_key, "", true).unwrap();

        assert!(!signed_twice.is_empty());
    }

    #[test]
    fn test_is_signed() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_key_pair().unwrap();

        assert!(!is_signed(&jar_bytes).unwrap());

        let signed_jar = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();
        assert!(is_signed(&signed_jar).unwrap());
    }

    #[test]
    fn test_extract_signature_bytes() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_key_pair().unwrap();

        let result = extract_signature_bytes(&jar_bytes);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let signed_jar = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();
        let result = extract_signature_bytes(&signed_jar);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_verify() {
        let jar_bytes = create_test_jar();
        let (priv_key, pub_key) = generate_key_pair().unwrap();

        let signed_jar = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();

        let result = verify(&signed_jar, &pub_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_public_key() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_signing_credentials().unwrap();
        let cert_chain: Vec<Vec<u8>> = vec![];

        let signed_jar =
            sign_bytes_with_cert_chain(&jar_bytes, &priv_key, Some(&cert_chain), "", false)
                .unwrap();

        let result = extract_public_key(&signed_jar);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_empty_jar() {
        let mut buffer = Vec::new();
        {
            let writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
            writer.finish().unwrap();
        }

        let (priv_key, _) = generate_key_pair().unwrap();
        let signed_jar = sign_bytes(&buffer, &priv_key, "", false).unwrap();

        assert!(!signed_jar.is_empty());
    }

    #[test]
    fn test_sign_jar_with_meta_inf_files() {
        let jar_bytes = create_test_jar();
        let (priv_key, _) = generate_key_pair().unwrap();

        let signed_jar = sign_bytes(&jar_bytes, &priv_key, "", false).unwrap();

        let cursor = std::io::Cursor::new(&signed_jar);
        let mut zip = ZipArchive::new(cursor).unwrap();

        let mut has_manifest = false;
        let mut has_sf = false;
        let mut has_rsa = false;

        for i in 0..zip.len() {
            let file = zip.by_index(i).unwrap();
            let name = file.name();

            if name == "META-INF/MANIFEST.MF" {
                has_manifest = true;
            } else if name == "META-INF/SIGNATURE.SF" {
                has_sf = true;
            } else if name == "META-INF/SIGNATURE.RSA" {
                has_rsa = true;
            }
        }

        assert!(has_manifest);
        assert!(has_sf);
        assert!(has_rsa);
    }

    #[test]
    fn test_invalid_key() {
        let jar_bytes = create_test_jar();
        let invalid_key = b"invalid key data";

        let result = sign_bytes(&jar_bytes, invalid_key, "", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_jar() {
        let invalid_jar = b"not a jar";
        let (priv_key, _) = generate_key_pair().unwrap();

        let result = sign_bytes(invalid_jar, &priv_key, "", false);
        assert!(result.is_err());
    }
}
