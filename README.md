# jarsigner

A Rust library and CLI tool for signing JAR files, compatible with the Java `jarsigner` tool API.

## Features

### Library
- **JAR Signing**: Sign JAR files with RSA private keys (PKCS#8 DER format)
- **Standard Compliance**: Follows the OpenJDK jarsigner specification for MANIFEST.MF, .SF, and .RSA file formats
- **Signature Override**: Option to remove existing signatures before applying new ones
- **Signature Detection**: Check if a JAR file is signed
- **Signature Verification**: Verify JAR signatures using public keys
- **Key Generation**: Generate RSA key pairs for signing

### CLI
- **Command-line Interface**: Simple CLI with subcommands using clap
- **Key Management**: Generate, store, and manage signing keys using OS keyring
- **Secure Storage**: Keys stored securely in system keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)
- **Easy Signing**: Sign JAR files with stored keys
- **Verification**: Verify JAR signatures with stored public keys

## Installation

### Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
jarsigned = "0.1.0"
```

### CLI

Build from source:

```bash
cd jarsigned
cargo build --release
```

The binary will be available at `target/release/jarsigned.exe` (Windows) or `target/release/jarsigned` (Unix).

## Usage

### CLI

Run the CLI:

```bash
jarsigned <SUBCOMMAND>
```

Available subcommands:

- **generate**: Generate a new RSA key pair and store it in the OS keyring
  ```bash
  jarsigned generate <name> [--passcode <passcode>]
  ```

- **sign**: Sign a JAR file using a stored key
  ```bash
  jarsigned sign <jar> <key> [--output <output>]
  ```

- **verify**: Verify a JAR signature (automatically tries all stored public keys)
  ```bash
  jarsigned verify <jar>
  ```

- **delete**: Remove a key from the keyring
  ```bash
  jarsigned delete <name>
  ```

#### Key Storage

Keys are stored in `~/.jarsigned/` directory. When generating a key, you provide:
- A key name (e.g., "default", "production", "development")
- An optional passcode (auto-generated if not provided)

The directory stores:
- `<name>.priv` - Private key (binary DER format)
- `<name>.pub` - Public key (binary DER format)
- Passcode is stored in OS keyring under service `jarsigned`

### Library Usage

#### Basic JAR Signing

```rust
use jarsigner::{sign_bytes, generate_key_pair};

// Generate a key pair
let (private_key, public_key) = generate_key_pair()?;

// Sign a JAR file
let jar_bytes = std::fs::read("my-app.jar")?;
let signed_jar = sign_bytes(&jar_bytes, &private_key, "", true)?;

std::fs::write("my-app-signed.jar", signed_jar)?;
```

#### Checking if a JAR is Signed

```rust
use jarsigner::is_signed;

let jar_bytes = std::fs::read("my-app.jar")?;
let signed = is_signed(&jar_bytes)?;
```

#### Verifying a Signature

```rust
use jarsigner::verify;

let jar_bytes = std::fs::read("my-app.jar")?;
let public_key = std::fs::read("public_key.der")?;
let valid = verify(&jar_bytes, &public_key)?;
```

#### Extracting Signature Block

```rust
use jarsigner::extract_signature_bytes;

let jar_bytes = std::fs::read("my-app.jar")?;
if let Some(sig_block) = extract_signature_bytes(&jar_bytes)? {
    println!("Signature block size: {} bytes", sig_block.len());
}
```

## API Compatibility

This library is designed to be API-compatible with the `jarsigner` crate, making it a drop-in replacement for existing codebases.

## JAR Signing Format

The library follows the standard jarsigner format:

- **MANIFEST.MF**: Contains SHA-256 digests of all files (excluding META-INF)
- **.SF file**: Contains digest of the manifest and individual file digests
- **.RSA file**: Contains the PKCS#1 RSA signature of the .SF file

## Limitations

- Certificate generation is not implemented in this version
- CMS/PKCS#7 signature blocks are simplified (raw RSA signature only)
- Full certificate chain verification is not supported
- CLI key listing is limited (keyring doesn't support enumeration)

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
