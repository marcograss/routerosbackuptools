use binread::{io::Cursor, BinRead, BinReaderExt};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{prelude::*, BufReader, Read};

const MAGIC_ENCRYPTED_RC4: u32 = 0x7291A8EF;
const MAGIC_ENCRYPTED_AES: u32 = 0x7391A8EF;
const MAGIC_PLAINTEXT: u32 = 0xB1A1AC88;

#[derive(BinRead, PartialEq, Debug)]
pub struct Header {
    magic: u32,
    length: u32,
}

impl Header {
    pub fn parse(raw: &Vec<u8>) -> Header {
        Cursor::new(raw).read_ne().unwrap()
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct RC4File {
    header: Header,
    #[br(count = 32)]
    salt: Vec<u8>,
    magic_check: u32,
}

impl RC4File {
    pub fn check_password(&self, password: &str) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut rc4 = Rc4::new(&hash);
        let skip: Vec<u8> = vec![0; 0x300];
        let mut skip_out: Vec<u8> = vec![0; 0x300];
        rc4.process(&skip, &mut skip_out);
        let mut output: Vec<u8> = vec![0; 4];
        rc4.process(&self.magic_check.to_le_bytes(), &mut output);
        // println!("{} {:?} {:?}", ascii_password, output, MAGIC_PLAINTEXT.to_le_bytes());
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct AESFile {
    header: Header,
    #[br(count = 32)]
    salt: Vec<u8>,
    // offset 40
    #[br(count = 30)]
    padding: Vec<u8>,
    magic_check: u32,
}

#[derive(BinRead, PartialEq, Debug)]
pub struct PlainTextFile {
    header: Header,
}

#[derive(PartialEq, Debug)]
pub enum WholeFile {
    RC4File(RC4File),
    AESFile(AESFile),
    PlainTextFile(PlainTextFile),
    InvalidFile,
}

impl WholeFile {
    pub fn parse(raw: &Vec<u8>) -> WholeFile {
        let h: Header = Header::parse(raw);
        match h.magic {
            MAGIC_ENCRYPTED_RC4 => WholeFile::RC4File(Cursor::new(raw).read_ne().unwrap()),
            MAGIC_ENCRYPTED_AES => WholeFile::AESFile(Cursor::new(raw).read_ne().unwrap()),
            MAGIC_PLAINTEXT => WholeFile::PlainTextFile(Cursor::new(raw).read_ne().unwrap()),
            _ => WholeFile::InvalidFile,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_header() {
        let file_content: Vec<u8> = vec![0x34, 0x12, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00];
        assert_eq!(
            Header::parse(&file_content),
            Header {
                magic: 0x1234,
                length: 0x5678
            }
        );
    }

    #[test]
    fn parse_rc4_file() {
        let mut file_content: Vec<u8> = vec![0xEF, 0xA8, 0x91, 0x72, 0x78, 0x56, 0x00, 0x00];
        let salt: Vec<u8> = vec![
            0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1,
            0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4,
        ];
        file_content.append(&mut salt.clone());
        let magic_check: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44];
        file_content.append(&mut magic_check.clone());
        assert_eq!(
            WholeFile::parse(&file_content),
            WholeFile::RC4File(RC4File {
                header: Header {
                    magic: MAGIC_ENCRYPTED_RC4,
                    length: 0x5678
                },
                salt: salt,
                magic_check: 0x44434241,
            })
        );
    }

    #[test]
    fn parse_aes_file() {
        let mut file_content: Vec<u8> = vec![0xEF, 0xA8, 0x91, 0x73, 0x78, 0x56, 0x00, 0x00];
        let salt: Vec<u8> = vec![
            0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1,
            0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4,
        ];
        file_content.append(&mut salt.clone());
        let padding: Vec<u8> = vec![0x2; 30];
        file_content.append(&mut padding.clone());
        let magic_check: Vec<u8> = vec![0x51, 0x52, 0x53, 0x54];
        file_content.append(&mut magic_check.clone());
        assert_eq!(
            WholeFile::parse(&file_content),
            WholeFile::AESFile(AESFile {
                header: Header {
                    magic: MAGIC_ENCRYPTED_AES,
                    length: 0x5678
                },
                salt: salt,
                padding: padding,
                magic_check: 0x54535251,
            })
        );
    }

    #[test]
    fn parse_plaintext_file() {
        let file_content: Vec<u8> = vec![0x88, 0xAC, 0xA1, 0xB1, 0x78, 0x56, 0x00, 0x00];
        assert_eq!(
            WholeFile::parse(&file_content),
            WholeFile::PlainTextFile(PlainTextFile {
                header: Header {
                    magic: MAGIC_PLAINTEXT,
                    length: 0x5678
                },
            })
        );
    }
}

pub fn read_file_to_bytes(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

pub fn read_wordlist_file(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let buf = BufReader::new(file);
    Ok(buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>())
}
