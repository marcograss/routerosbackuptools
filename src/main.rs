use clap::{App, Arg, SubCommand};
use rayon::prelude::*;

use routerosbackuptools::*;

fn info_file(input_file: &str) {
    // println!("info {}", input_file);
    println!("** Backup Info **");
    if let Ok(content) = read_file_to_bytes(input_file) {
        match WholeFile::parse(&content) {
            WholeFile::RC4File(f) => {
                // println!("rc4 {:?}", f);
                println!("RouterOS Encrypted Backup (rc4-sha1)");
                println!("Length: {} bytes", f.header.length);
                println!("Salt (hex): {:x?}", f.salt);
                println!("Magic Check (hex): {:x?}", f.magic_check);
            }
            WholeFile::AESFile(f) => {
                // println!("aes {:?}", f);
                println!("RouterOS Encrypted Backup (aes128-ctr-sha256)");
                println!("Length: {} bytes", f.header.length);
                println!("Salt (hex): {:x?}", f.salt);
                println!("Signature: {:x?}", f.signature);
                println!("Magic Check (hex): {:x?}", f.magic_check);
            }
            WholeFile::PlainTextFile(f) => {
                // println!("plaintext {:?}", f);
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
    // println!("decrypt {} {} {}", input_file, output_file, password);
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
                    let decrypted = f.decrypt(&content, password);
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
    println!(
        "encrypt {} {} {} {}",
        input_file, output_file, password, algo
    );
    println!("** Encrypt Backup **");
}

fn unpack_file(input_file: &str, output_dir: &str) {
    // println!("unpack {} {}", input_file, output_dir);
    println!("** Unpack Backup **");
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
                // TODO
            }
            WholeFile::InvalidFile => {
                println!("Invalid file!");
                println!("Cannot unpack!");
            }
        };
    } else {
        println!("cannot read the input file");
    }
}

fn pack_file(input_dir: &str, output_file: &str) {
    println!("pack {} {}", input_dir, output_file);
    println!("** Pack Backup **");
}

fn bruteforce_file(input_file: &str, wordlist_file: &str, parallel: bool) {
    // println!("bruteforce {} {} {}", input_file, wordlist_file, parallel);
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
                    // println!("rc4 {:?}", f);
                    if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                        println!("Password found: {}", found);
                    } else {
                        println!("Password NOT found");
                    }
                }
                WholeFile::AESFile(f) => {
                    // println!("aes {:?}", f);
                    if let Some(found) = wordlist.par_iter().find_any(|&w| f.check_password(w)) {
                        println!("Password found: {}", found);
                    } else {
                        println!("Password NOT found");
                    }
                }
                WholeFile::PlainTextFile(_) => {
                    // println!("plaintext {:?}", f);
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
    println!("{:?}", matches);
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
