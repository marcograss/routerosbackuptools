use anyhow::{anyhow, Result};
use clap::{builder::PossibleValue, Arg, ArgAction, Command};
use rayon::prelude::*;
use std::fs;
use std::path::Path;

use routerosbackuptools::{
    read_file_to_bytes, read_wordlist_file, write_bytes_to_file, AESFile, PackedFile,
    PlainTextFile, RC4File, WholeFile,
};

fn info_file(input_file: &str) -> Result<()> {
    println!("** Backup Info **");
    let content = read_file_to_bytes(input_file)?;
    match WholeFile::parse(&content) {
        WholeFile::RC4File(f) => {
            println!("RouterOS Encrypted Backup (rc4-sha1)");
            println!("Length: {} bytes", f.header.length);
            println!("Salt (hex): {:x?}", f.salt);
            println!("Magic Check (hex): {:x?}", f.magic_check);
            Ok(())
        }
        WholeFile::AESFile(f) => {
            println!("RouterOS Encrypted Backup (aes128-ctr-sha256)");
            println!("Length: {} bytes", f.header.length);
            println!("Salt (hex): {:x?}", f.salt);
            println!("Signature: {:x?}", f.signature);
            println!("Magic Check (hex): {:x?}", f.magic_check);
            Ok(())
        }
        WholeFile::PlainTextFile(f) => {
            println!("RouterOS Plaintext Backup");
            println!("Length: {} bytes", f.header.length);
            Ok(())
        }
        WholeFile::InvalidFile => Err(anyhow!("Invalid file!")),
    }
}

fn decrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<()> {
    println!("** Decrypt Backup **");
    info_file(input_file)?;
    let content = read_file_to_bytes(input_file)?;
    match WholeFile::parse(&content) {
        WholeFile::RC4File(f) => {
            if f.check_password(password) {
                println!("Correct password!");
                println!("Decrypting...");
                let decrypted = f.decrypt(&content, password)?;
                write_bytes_to_file(&decrypted, output_file)?;
                Ok(())
            } else {
                Err(anyhow!("Wrong password!\nCannot decrypt!"))
            }
        }
        WholeFile::AESFile(f) => {
            if f.check_password(password) {
                println!("Correct password!");
                println!("Decrypting...");
                let decrypted = match f.decrypt(&content, password) {
                    Ok(decrypted) => {
                        println!("Decrypted correctly");
                        decrypted
                    }
                    Err(decrypted) => {
                        println!(
                            "Decryption completed, but HMAC check failed - file has been modified!"
                        );
                        decrypted
                    }
                };
                write_bytes_to_file(&decrypted, output_file)?;
                Ok(())
            } else {
                Err(anyhow!("Wrong password!\nCannot decrypt!"))
            }
        }
        WholeFile::PlainTextFile(_) => Err(anyhow!("No decryption needed!")),
        WholeFile::InvalidFile => Err(anyhow!("Invalid file!")),
    }
}

fn encrypt_file(input_file: &str, output_file: &str, password: &str, algo: &str) -> Result<()> {
    println!("** Encrypt Backup **");
    let content = read_file_to_bytes(input_file)?;
    match WholeFile::parse(&content) {
        WholeFile::RC4File(_) | WholeFile::AESFile(_) => {
            println!("RouterOS Encrypted Backup");
            println!("No encryption needed!");
            Ok(())
        }
        WholeFile::PlainTextFile(f) => {
            println!("RouterOS Plaintext Backup");
            println!("Length: {} bytes", f.header.length);
            let encrypted = match algo {
                "RC4" => {
                    println!("encrypt rc4");
                    RC4File::encrypt(&content, password)
                }
                "AES" => {
                    println!("encrypt aes");
                    AESFile::encrypt(&content, password)
                }
                _ => {
                    return Err(anyhow!("invalid encryption algorithm"));
                }
            }?;
            write_bytes_to_file(&encrypted, output_file)?;
            Ok(())
        }
        WholeFile::InvalidFile => Err(anyhow!("Invalid file!")),
    }
}

fn unpack_file(input_file: &str, output_dir: &str) -> Result<()> {
    // println!("unpack {} {}", input_file, output_dir);
    println!("** Unpack Backup **");
    let output_dir = Path::new(output_dir);
    if output_dir.exists() {
        return Err(anyhow!(
            "Directory {} already exists, cannot extract!",
            output_dir.display()
        ));
    }

    let content = read_file_to_bytes(input_file)?;
    match WholeFile::parse(&content) {
        WholeFile::RC4File(_) | WholeFile::AESFile(_) => {
            println!("RouterOS Encrypted Backup");
            println!("Cannot unpack encrypted backup!");
            println!("Decrypt backup first!");
            Ok(())
        }
        WholeFile::PlainTextFile(f) => {
            println!("RouterOS Plaintext Backup");
            println!("Length: {} bytes", f.header.length);
            println!("Extracting backup...");
            let unpacked_files = f.unpack_files(&content);
            let files_num = unpacked_files.len();
            if files_num > 0 {
                if fs::create_dir(output_dir).is_ok() {
                    for f in &unpacked_files {
                        let idx = output_dir
                            .join(Path::new(&format!("{}.idx", &f.name)))
                            .into_os_string()
                            .into_string()
                            .unwrap();
                        let dat = output_dir
                            .join(Path::new(&format!("{}.dat", &f.name)))
                            .into_os_string()
                            .into_string()
                            .unwrap();
                        if let Err(e) = write_bytes_to_file(&f.idx, &idx) {
                            println!("Cannot write {}: {}", idx, e);
                        }
                        if let Err(e) = write_bytes_to_file(&f.dat, &dat) {
                            println!("Cannot write {}: {}", dat, e);
                        }
                    }
                    println!(
                        "Wrote {} files pair in: {}",
                        files_num,
                        output_dir.display()
                    );
                    Ok(())
                } else {
                    Err(anyhow!(
                        "Cannot create the {} directory",
                        output_dir.display()
                    ))
                }
            } else {
                Ok(())
            }
        }
        WholeFile::InvalidFile => Err(anyhow!("Invalid file!")),
    }
}

fn pack_file(input_dir: &str, output_file: &str) -> Result<()> {
    println!("** Pack Backup **");
    let mut files_to_pack: Vec<PackedFile> = Vec::new();
    let input_dir = Path::new(input_dir);
    if !input_dir.exists() {
        return Err(anyhow!(
            "The input directory {} does not exist",
            input_dir.display()
        ));
    }
    if !input_dir.is_dir() {
        return Err(anyhow!("{} is not a directory", input_dir.display()));
    }
    let files = fs::read_dir(input_dir)?;
    for f in files.flatten() {
        let path = f.path();
        let extension_obj = path.extension();
        if let Some(extension_obj) = extension_obj {
            let extension = extension_obj;
            if extension == "idx" {
                let stripped_filename = path.file_stem().unwrap().to_str().unwrap();
                let dat_filename = input_dir.join(format!("{}.dat", stripped_filename));
                let dat_path = Path::new(&dat_filename);
                if dat_path.exists() {
                    files_to_pack.push(PackedFile {
                        name: stripped_filename.to_string(),
                        idx: read_file_to_bytes(path.to_str().unwrap())?,
                        dat: read_file_to_bytes(dat_path.to_str().unwrap())?,
                    });
                }
            }
        }
    }
    if !files_to_pack.is_empty() {
        println!(
            "Packing {} files from {} into {}",
            files_to_pack.len(),
            input_dir.display(),
            output_file
        );
        let packed = PlainTextFile::pack_files(&files_to_pack)?;
        write_bytes_to_file(&packed, output_file)?;
    }
    Ok(())
}

fn bruteforce_file(input_file: &str, wordlist_file: &str, parallel: bool) -> Result<()> {
    println!("** Bruteforce Backup Password **");
    if !parallel {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global()?;
    }
    info_file(input_file)?;
    let wordlist = read_wordlist_file(wordlist_file)?;
    let content = read_file_to_bytes(input_file)?;
    match WholeFile::parse(&content) {
        WholeFile::RC4File(f) => {
            if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                println!("Password found: {}", found);
            } else {
                println!("Password NOT found");
            }
            Ok(())
        }
        WholeFile::AESFile(f) => {
            if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                println!("Password found: {}", found);
            } else {
                println!("Password NOT found");
            }
            Ok(())
        }
        WholeFile::PlainTextFile(_) => Err(anyhow!("No Decryption Needed.")),
        WholeFile::InvalidFile => Err(anyhow!("Invalid File")),
    }
}

fn main() -> Result<()> {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("info").arg(
                Arg::new("input")
                    .short('i')
                    .help("input file")
                    .required(true),
            ),
        )
        .subcommand(
            Command::new("decrypt")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .help("encrypted input file")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .help("decrypted output file")
                        .required(true),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .help("encryption password")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("encrypt")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .help("input file to encrypt")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .help("encrypted output file")
                        .required(true),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .help("encryption password")
                        .required(true),
                )
                .arg(
                    Arg::new("algo")
                        .short('e')
                        .help("encryption algorithm")
                        .required(true)
                        .value_parser([PossibleValue::new("AES"), PossibleValue::new("RC4")]),
                ),
        )
        .subcommand(
            Command::new("unpack")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .help("input file to unpack")
                        .required(true),
                )
                .arg(
                    Arg::new("directory")
                        .short('d')
                        .help("output directory")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("pack")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .help("packed output file")
                        .required(true),
                )
                .arg(
                    Arg::new("directory")
                        .short('d')
                        .help("input directory to pack")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("bruteforce")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .help("encrypted input file")
                        .required(true),
                )
                .arg(
                    Arg::new("wordlist")
                        .short('w')
                        .help("wordlist txt with the passwords to try")
                        .required(true),
                )
                .arg(
                    Arg::new("parallel")
                        .short('p')
                        .help("bruteforce with parallelism")
                        .action(ArgAction::SetTrue),
                ),
        )
        .get_matches();
    let result = match matches.subcommand() {
        Some(("info", sub_m)) => info_file(sub_m.get_one::<String>("input").unwrap()),
        Some(("decrypt", sub_m)) => decrypt_file(
            sub_m.get_one::<String>("input").unwrap(),
            sub_m.get_one::<String>("output").unwrap(),
            sub_m.get_one::<String>("password").unwrap(),
        ),
        Some(("encrypt", sub_m)) => encrypt_file(
            sub_m.get_one::<String>("input").unwrap(),
            sub_m.get_one::<String>("output").unwrap(),
            sub_m.get_one::<String>("password").unwrap(),
            sub_m.get_one::<String>("algo").unwrap(),
        ),
        Some(("unpack", sub_m)) => unpack_file(
            sub_m.get_one::<String>("input").unwrap(),
            sub_m.get_one::<String>("directory").unwrap(),
        ),
        Some(("pack", sub_m)) => pack_file(
            sub_m.get_one::<String>("directory").unwrap(),
            sub_m.get_one::<String>("output").unwrap(),
        ),
        Some(("bruteforce", sub_m)) => bruteforce_file(
            sub_m.get_one::<String>("input").unwrap(),
            sub_m.get_one::<String>("wordlist").unwrap(),
            sub_m.get_flag("parallel"),
        ),
        _ => Ok(()),
    };
    if let Err(e) = result {
        eprintln!("{}", e);
    }
    Ok(())
}
