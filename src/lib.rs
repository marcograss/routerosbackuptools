use binread::{io::Cursor, BinRead, BinReaderExt};
use crypto::aes;
use crypto::aes::KeySize;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader, Read};

const MAGIC_ENCRYPTED_RC4: u32 = 0x7291A8EF;
const MAGIC_ENCRYPTED_AES: u32 = 0x7391A8EF;
const MAGIC_PLAINTEXT: u32 = 0xB1A1AC88;

#[derive(BinRead, PartialEq, Debug)]
pub struct Header {
    pub magic: u32,
    pub length: u32,
}

impl Header {
    pub fn parse(raw: &[u8]) -> Header {
        Cursor::new(raw).read_ne().unwrap()
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct RC4File {
    pub header: Header,
    #[br(count = 32)]
    pub salt: Vec<u8>,
    pub magic_check: u32,
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
        // println!("{} {:?} {:?}", password, output, MAGIC_PLAINTEXT.to_le_bytes());
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    pub fn decrypt(&self, file_content: &[u8], password: &str) -> Vec<u8> {
        let mut decrypted = Vec::new();
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
        let to_decrypt = &file_content[44..]; // skip magic, length, salt, magic_check
        decrypted.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 44 + 8).try_into().unwrap();
        decrypted.append(&mut content_len.to_le_bytes().to_vec());
        let mut temp: Vec<u8> = vec![0; file_content.len() - 44];
        rc4.process(to_decrypt, &mut temp);
        decrypted.append(&mut temp);
        decrypted
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct AESFile {
    pub header: Header,
    #[br(count = 32)]
    pub salt: Vec<u8>,
    // offset 40
    #[br(count = 32)]
    pub signature: Vec<u8>,
    pub magic_check: u32,
}

impl AESFile {
    pub fn check_password(&self, password: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = &hasher.finalize()[0..16];
        let mut aes_ctr = aes::ctr(KeySize::KeySize128, hash, &self.salt[0..16]);
        let skip: Vec<u8> = vec![0; 0x10];
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.process(&skip, &mut skip_out);
        let mut output: Vec<u8> = vec![0; 4];
        aes_ctr.process(&self.magic_check.to_le_bytes(), &mut output);
        // println!("{} {:?} {:?}", password, output, MAGIC_PLAINTEXT.to_le_bytes());
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    pub fn decrypt(&self, file_content: &[u8], password: &str) -> Vec<u8> {
        let mut decrypted = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = &hasher.finalize()[0..16];
        let mut aes_ctr = aes::ctr(KeySize::KeySize128, hash, &self.salt[0..16]);
        let skip: Vec<u8> = vec![0; 0x10];
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.process(&skip, &mut skip_out);
        let mut output: Vec<u8> = vec![0; 4];
        aes_ctr.process(&self.magic_check.to_le_bytes(), &mut output);
        let to_decrypt = &file_content[76..]; // skip magic, length, salt/nonce, hmac magic_check
        decrypted.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 76 + 8).try_into().unwrap();
        decrypted.append(&mut content_len.to_le_bytes().to_vec());
        let mut temp: Vec<u8> = vec![0; file_content.len() - 76];
        aes_ctr.process(to_decrypt, &mut temp);
        decrypted.append(&mut temp);
        decrypted
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct PlainTextFile {
    pub header: Header,
}

#[derive(PartialEq, Debug)]
pub enum WholeFile {
    RC4File(RC4File),
    AESFile(AESFile),
    PlainTextFile(PlainTextFile),
    InvalidFile,
}

impl WholeFile {
    pub fn parse(raw: &[u8]) -> WholeFile {
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
        let signature: Vec<u8> = vec![0x2; 32];
        file_content.append(&mut signature.clone());
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
                signature: signature,
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

    #[test]
    fn check_rc4_password() {
        let file_content: Vec<u8> = vec![
            0xef, 0xa8, 0x91, 0x72, 0xc9, 0xb7, 0x01, 0x00, 0x11, 0xee, 0x71, 0x06, 0x35, 0xef,
            0x99, 0x51, 0x63, 0xd8, 0x87, 0x81, 0x0a, 0xe9, 0x6d, 0xc4, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0xf4,
            0x29, 0x35,
        ];
        if let WholeFile::RC4File(f) = WholeFile::parse(&file_content) {
            assert_eq!(true, f.check_password("modificailrouter"));
        } else {
            panic!("We didn't get a RC4File");
        }
    }

    #[test]
    fn check_aes_password() {
        let file_content: Vec<u8> = vec![
            0xef, 0xa8, 0x91, 0x73, 0x4c, 0x00, 0x00, 0x00, 0x91, 0xdd, 0x32, 0x9b, 0x03, 0x32,
            0xfb, 0x96, 0xf4, 0x4a, 0x1b, 0xdf, 0x8c, 0x08, 0x6f, 0x52, 0xca, 0xba, 0x67, 0xfa,
            0xd4, 0x45, 0x75, 0x55, 0x16, 0xf4, 0xa8, 0xd0, 0xae, 0xcb, 0x9d, 0x28, 0x8b, 0x04,
            0x39, 0x4f, 0xef, 0x0b, 0xe0, 0x7f, 0x95, 0xb7, 0x09, 0xf7, 0xb1, 0xb3, 0xc8, 0x78,
            0xcb, 0x5f, 0x41, 0xd2, 0xcb, 0xe0, 0xff, 0x5d, 0x78, 0x92, 0xef, 0x30, 0x40, 0xd3,
            0xa4, 0x63, 0xb2, 0xc2, 0x81, 0x07,
        ];
        if let WholeFile::AESFile(f) = WholeFile::parse(&file_content) {
            assert_eq!(true, f.check_password("aespass"));
        } else {
            panic!("We didn't get a AESFile");
        }
    }

    #[test]
    fn check_rc4_decryption() {
        let file_content: Vec<u8> = vec![
            0xef, 0xa8, 0x91, 0x72, 0xc9, 0xb7, 0x01, 0x00, 0x11, 0xee, 0x71, 0x06, 0x35, 0xef,
            0x99, 0x51, 0x63, 0xd8, 0x87, 0x81, 0x0a, 0xe9, 0x6d, 0xc4, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0xf4,
            0x29, 0x35,
        ];
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        if let WholeFile::RC4File(f) = WholeFile::parse(&file_content) {
            assert_eq!(
                decrypted_content,
                f.decrypt(&file_content, "modificailrouter")
            );
        } else {
            panic!("We didn't get a RC4File");
        }
    }

    #[test]
    fn check_aes_decryption() {
        let file_content: Vec<u8> = vec![
            0xef, 0xa8, 0x91, 0x73, 0x4c, 0x00, 0x00, 0x00, 0x91, 0xdd, 0x32, 0x9b, 0x03, 0x32,
            0xfb, 0x96, 0xf4, 0x4a, 0x1b, 0xdf, 0x8c, 0x08, 0x6f, 0x52, 0xca, 0xba, 0x67, 0xfa,
            0xd4, 0x45, 0x75, 0x55, 0x16, 0xf4, 0xa8, 0xd0, 0xae, 0xcb, 0x9d, 0x28, 0x8b, 0x04,
            0x39, 0x4f, 0xef, 0x0b, 0xe0, 0x7f, 0x95, 0xb7, 0x09, 0xf7, 0xb1, 0xb3, 0xc8, 0x78,
            0xcb, 0x5f, 0x41, 0xd2, 0xcb, 0xe0, 0xff, 0x5d, 0x78, 0x92, 0xef, 0x30, 0x40, 0xd3,
            0xa4, 0x63, 0xb2, 0xc2, 0x81, 0x07,
        ];
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        if let WholeFile::AESFile(f) = WholeFile::parse(&file_content) {
            assert_eq!(decrypted_content, f.decrypt(&file_content, "aespass"));
        } else {
            panic!("We didn't get a AESFile");
        }
    }
}

pub fn read_file_to_bytes(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

pub fn write_bytes_to_file(content: &[u8], filename: &str) -> std::io::Result<()> {
    let mut file = File::open(filename)?;
    file.write_all(content)?;
    Ok(())
}

pub fn read_wordlist_file(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let buf = BufReader::new(file);
    Ok(buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>())
}
