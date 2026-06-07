use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "jarsigned")]
#[command(about = "JAR signing tool compatible with jarsigner API", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        name: String,
        #[arg(short, long)]
        passcode: Option<String>,
    },
    Sign {
        jar: String,
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        output: Option<String>,
    },
    Verify {
        jar: String,
    },
    Delete {
        name: String,
    },
}

fn get_keys_dir() -> Result<PathBuf> {
    let mut dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    dir.push(".jarsigned");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { name, passcode } => {
            let keys_dir = get_keys_dir()?;
            let priv_key_path = keys_dir.join(format!("{}.priv", name));
            let pub_key_path = keys_dir.join(format!("{}.pub", name));

            if priv_key_path.exists() || pub_key_path.exists() {
                anyhow::bail!("Key '{}' already exists. Use delete command first or choose a different name.", name);
            }

            let pb = spinner("Generating RSA key pair…");
            
            let passcode = if let Some(p) = passcode {
                p
            } else {
                let mut bytes = [0u8; 8];
                rand::thread_rng().fill_bytes(&mut bytes);
                hex::encode(bytes)
            };

            let (private_key, public_key) = jarsigner::generate_key_pair()?;

            std::fs::write(&priv_key_path, &private_key)?;
            std::fs::write(&pub_key_path, &public_key)?;

            let entry = keyring::Entry::new("jarsigned", &name)?;
            entry.set_password(&passcode)?;

            pb.finish_and_clear();

            println!("{} Key generated successfully", "✓".green().bold());
            println!("  Name:        {}", name.cyan());
            println!("  Private key: {}", priv_key_path.display().to_string().dimmed());
            println!("  Public key:  {}", pub_key_path.display().to_string().dimmed());
        }
        Commands::Sign { jar, key, output } => {
            let keys_dir = get_keys_dir()?;
            let key_name = key.unwrap_or_else(|| "default".to_string());
            let priv_key_path = keys_dir.join(format!("{}.priv", key_name));
            
            if !priv_key_path.exists() {
                anyhow::bail!("Key '{}' not found. Use generate command first or specify a different key with --key.", key_name);
            }
            
            let private_key = std::fs::read(&priv_key_path)?;

            let jar_bytes = std::fs::read(&jar)?;
            
            let pb = spinner("Signing JAR file…");
            let mut file_count = 0;
            
            let signed_jar = jarsigner::sign_bytes_with_cert_chain(&jar_bytes, &private_key, None, "", true, |_name, done| {
                if done {
                    file_count += 1;
                    pb.set_message(format!("Signed {} files…", file_count));
                }
            })?;

            pb.finish_and_clear();
            
            let output_path = output.unwrap_or(jar);
            std::fs::write(&output_path, signed_jar)?;

            println!("{} JAR signed successfully", "✓".green().bold());
            println!("  Key:    {}", key_name.cyan());
            println!("  Output: {}", output_path.dimmed());
        }
        Commands::Verify { jar } => {
            let pb = spinner("Reading JAR file…");
            let jar_bytes = std::fs::read(&jar)?;
            let is_signed = jarsigner::is_signed(&jar_bytes)?;

            if !is_signed {
                pb.finish_and_clear();
                println!("{} JAR is not signed", "✗".red().bold());
                return Ok(());
            }

            pb.set_message("Verifying signature…");
            
            let keys_dir = get_keys_dir()?;
            let entries = std::fs::read_dir(&keys_dir)?;
            let mut found_valid = false;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "pub") {
                    let public_key = std::fs::read(&path)?;
                    if let Ok(is_valid) = jarsigner::verify(&jar_bytes, &public_key) {
                        if is_valid {
                            let key_name = path.file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("unknown");
                            pb.finish_and_clear();
                            println!("{} JAR signature is valid", "✓".green().bold());
                            println!("  Verified with key: {}", key_name.cyan());
                            found_valid = true;
                            break;
                        }
                    }
                }
            }

            if !found_valid {
                pb.finish_and_clear();
                println!("{} JAR signature is invalid", "✗".red().bold());
                println!("  No matching public key found");
            }
        }
        Commands::Delete { name } => {
            let pb = spinner("Deleting key…");
            
            let keys_dir = get_keys_dir()?;
            let priv_key_path = keys_dir.join(format!("{}.priv", name));
            let pub_key_path = keys_dir.join(format!("{}.pub", name));

            let _ = std::fs::remove_file(&priv_key_path);
            let _ = std::fs::remove_file(&pub_key_path);

            let entry = keyring::Entry::new("jarsigned", &name)?;
            let _ = entry.delete_password();

            pb.finish_and_clear();

            println!("{} Key deleted successfully", "✓".green().bold());
            println!("  Name: {}", name.cyan());
        }
    }

    Ok(())
}
