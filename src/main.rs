use clap::{App, Arg, SubCommand};
use rayon::prelude::*;
use std::fs;
use std::path::Path;

use routerosbackuptools::{
    read_file_to_bytes, read_wordlist_file, write_bytes_to_file, AESFile, PackedFile,
    PlainTextFile, RC4File, WholeFile,
};

fn info_file(input_file: &str) {
    println!("** Backup Info **");
    if let Ok(content) = read_file_to_bytes(input_file) {
        match WholeFile::parse(&content) {
            WholeFile::RC4File(f) => {
                println!("RouterOS Encrypted Backup (rc4-sha1)");
                println!("Length: {} bytes", f.header.length);
                println!("Salt (hex): {:x?}", f.salt);
                println!("Magic Check (hex): {:x?}", f.magic_check);
            }
            WholeFile::AESFile(f) => {
                println!("RouterOS Encrypted Backup (aes128-ctr-sha256)");
                println!("Length: {} bytes", f.header.length);
                println!("Salt (hex): {:x?}", f.salt);
                println!("Signature: {:x?}", f.signature);
                println!("Magic Check (hex): {:x?}", f.magic_check);
            }
            WholeFile::PlainTextFile(f) => {
                println!("RouterOS Plaintext Backup");
                println!("Length: {} bytes", f.header.length);
            }
            WholeFile::InvalidFile => println!("Invalid file!"),
        };
    } else {
        println!("cannot read the input file");
    }
}

fn decrypt_file(input_file: &str, output_file: &str, password: &str) {
    println!("** Decrypt Backup **");
    info_file(input_file);
    if let Ok(content) = read_file_to_bytes(input_file) {
        match WholeFile::parse(&content) {
            WholeFile::RC4File(f) => {
                if f.check_password(password) {
                    println!("Correct password!");
                    println!("Decrypting...");
                    let decrypted = f.decrypt(&content, password);
                    write_bytes_to_file(&decrypted, output_file).expect("Can't write output file");
                } else {
                    println!("Wrong password!");
                    println!("Cannot decrypt!");
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
                            println!("Decryption completed, but HMAC check failed - file has been modified!");
                            decrypted
                        }
                    };
                    write_bytes_to_file(&decrypted, output_file).expect("Can't write output file");
                } else {
                    println!("Wrong password!");
                    println!("Cannot decrypt!");
                }
            }
            WholeFile::PlainTextFile(_) => {
                println!("No decryption needed!");
            }
            WholeFile::InvalidFile => println!("Invalid file!"),
        };
    } else {
        println!("cannot read the input file");
    }
}

fn encrypt_file(input_file: &str, output_file: &str, password: &str, algo: &str) {
    println!("** Encrypt Backup **");
    if let Ok(content) = read_file_to_bytes(input_file) {
        match WholeFile::parse(&content) {
            WholeFile::RC4File(_) | WholeFile::AESFile(_) => {
                println!("RouterOS Encrypted Backup");
                println!("No encryption needed!");
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
                        panic!("invalid encryption algorithm");
                    }
                };
                write_bytes_to_file(&encrypted, output_file).expect("Can't write output file");
            }
            WholeFile::InvalidFile => println!("Invalid file!"),
        };
    } else {
        println!("cannot read the input file");
    }
}

fn unpack_file(input_file: &str, output_dir: &str) {
    // println!("unpack {} {}", input_file, output_dir);
    println!("** Unpack Backup **");
    let output_dir = Path::new(output_dir);
    if output_dir.exists() {
        println!(
            "Directory {} already exists, cannot extract!",
            output_dir.display()
        );
        return;
    }

    if let Ok(content) = read_file_to_bytes(input_file) {
        match WholeFile::parse(&content) {
            WholeFile::RC4File(_) | WholeFile::AESFile(_) => {
                println!("RouterOS Encrypted Backup");
                println!("Cannot unpack encrypted backup!");
                println!("Decrypt backup first!");
            }
            WholeFile::PlainTextFile(f) => {
                println!("RouterOS Plaintext Backup");
                println!("Length: {} bytes", f.header.length);
                println!("Extracting backup...");
                let unpacked_files = f.unpack_files(&content);
                let files_num = unpacked_files.len();
                if files_num > 0 {
                    if fs::create_dir(output_dir).is_ok() {
                        for f in unpacked_files.iter() {
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
                            if write_bytes_to_file(&f.idx, &idx).is_err() {
                                println!("Cannot write {}", idx);
                            }
                            if write_bytes_to_file(&f.dat, &dat).is_err() {
                                println!("Cannot write {}", dat);
                            }
                        }
                        println!(
                            "Wrote {} files pair in: {}",
                            files_num,
                            output_dir.display()
                        );
                    } else {
                        println!("Cannot create the {} directory", output_dir.display());
                    }
                }
            }
            WholeFile::InvalidFile => println!("Invalid file!"),
        };
    } else {
        println!("cannot read the input file");
    }
}

fn pack_file(input_dir: &str, output_file: &str) {
    println!("** Pack Backup **");
    let mut files_to_pack: Vec<PackedFile> = Vec::new();
    let input_dir = Path::new(input_dir);
    if !input_dir.exists() {
        println!("The input directory {} does not exist", input_dir.display());
        return;
    }
    if !input_dir.is_dir() {
        println!("{} is not a directory", input_dir.display());
    }
    let files = fs::read_dir(input_dir).unwrap();
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
                        idx: read_file_to_bytes(path.to_str().unwrap()).unwrap(),
                        dat: read_file_to_bytes(dat_path.to_str().unwrap()).unwrap(),
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
        let packed = PlainTextFile::pack_files(&files_to_pack);
        if let Err(e) = write_bytes_to_file(&packed, output_file) {
            println!("Error writing the packed file {}", e);
        }
    }
}

fn bruteforce_file(input_file: &str, wordlist_file: &str, parallel: bool) {
    println!("** Bruteforce Backup Password **");
    if !parallel {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global()
            .unwrap();
    }
    info_file(input_file);
    if let Ok(wordlist) = read_wordlist_file(wordlist_file) {
        if let Ok(content) = read_file_to_bytes(input_file) {
            match WholeFile::parse(&content) {
                WholeFile::RC4File(f) => {
                    if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                        println!("Password found: {}", found);
                    } else {
                        println!("Password NOT found");
                    }
                }
                WholeFile::AESFile(f) => {
                    if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                        println!("Password found: {}", found);
                    } else {
                        println!("Password NOT found");
                    }
                }
                WholeFile::PlainTextFile(_) => {
                    println!("No Decryption Needed.")
                }
                WholeFile::InvalidFile => println!("Invalid File"),
            };
        } else {
            println!("cannot read the file");
        }
    } else {
        println!("cannot read the wordlist");
    }
}

fn main() {
    let matches = App::new("routerosbackuptools")
        .version("1.0")
        .author("marcograss <marco.gra@gmail.com>")
        .about("Tool to encrypt/decrypt and pack/unpack RouterOS v6.13+ backup files")
        .subcommand(
            SubCommand::with_name("info").arg(
                Arg::with_name("input")
                    .short("i")
                    .help("input file")
                    .required(true)
                    .takes_value(true),
            ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .help("encrypted input file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .help("decrypted output file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .help("encryption password")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .help("input file to encrypt")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .help("encrypted output file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .help("encryption password")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("algo")
                        .short("e")
                        .help("encryption algorithm")
                        .required(true)
                        .takes_value(true)
                        .possible_values(&["AES", "RC4"]),
                ),
        )
        .subcommand(
            SubCommand::with_name("unpack")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .help("input file to unpack")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("directory")
                        .short("d")
                        .help("output directory")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("pack")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .help("packed output file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("directory")
                        .short("d")
                        .help("input directory to pack")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("bruteforce")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .help("encrypted input file")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("wordlist")
                        .short("w")
                        .help("wordlist txt with the passwords to try")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("parallel")
                        .short("p")
                        .help("bruteforce with parallelism"),
                ),
        )
        .get_matches();
    match matches.subcommand() {
        ("info", Some(sub_m)) => info_file(sub_m.value_of("input").unwrap()),
        ("decrypt", Some(sub_m)) => decrypt_file(
            sub_m.value_of("input").unwrap(),
            sub_m.value_of("output").unwrap(),
            sub_m.value_of("password").unwrap(),
        ),
        ("encrypt", Some(sub_m)) => encrypt_file(
            sub_m.value_of("input").unwrap(),
            sub_m.value_of("output").unwrap(),
            sub_m.value_of("password").unwrap(),
            sub_m.value_of("algo").unwrap(),
        ),
        ("unpack", Some(sub_m)) => unpack_file(
            sub_m.value_of("input").unwrap(),
            sub_m.value_of("directory").unwrap(),
        ),
        ("pack", Some(sub_m)) => pack_file(
            sub_m.value_of("directory").unwrap(),
            sub_m.value_of("output").unwrap(),
        ),
        ("bruteforce", Some(sub_m)) => bruteforce_file(
            sub_m.value_of("input").unwrap(),
            sub_m.value_of("wordlist").unwrap(),
            sub_m.is_present("parallel"),
        ),
        _ => unimplemented!(),
    }
}
