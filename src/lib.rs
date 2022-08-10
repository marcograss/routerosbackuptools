#![warn(missing_docs)]
//! Tools to encrypt/decrypt and pack/unpack RouterOS v6.13+ backup files

use binread::{io::Cursor, BinRead, BinReaderExt, BinResult};
use binwrite::BinWrite;
use crypto::aes;
use crypto::aes::KeySize;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader, Read};
use std::str;

const MAGIC_ENCRYPTED_RC4: u32 = 0x7291A8EF;
const MAGIC_ENCRYPTED_AES: u32 = 0x7391A8EF;
const MAGIC_PLAINTEXT: u32 = 0xB1A1AC88;

type HmacSha256 = Hmac<Sha256>;

/// Common Header for the router files
#[derive(BinRead, PartialEq, Debug)]
pub struct Header {
    /// Magic to identify the filetype
    pub magic: u32,
    /// Length of the file
    pub length: u32,
}

impl Header {
    /// Parse a header from raw bytes
    pub fn parse(raw: &[u8]) -> Header {
        Cursor::new(raw).read_le().unwrap()
    }
}

/// RC4 type of file, encrypted with the rc4
#[derive(BinRead, PartialEq, Debug)]
pub struct RC4File {
    /// The generic header
    pub header: Header,
    /// salt for encryption
    #[br(count = 32)]
    pub salt: Vec<u8>,
    /// Magic to check if the decryption is correct
    pub magic_check: u32,
}

impl RC4File {
    /// Check if the rc4 file password is correct or not
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
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    /// decrypt the rc4 file content
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

    /// Encrypt a file content to this rc4 format
    pub fn encrypt(file_content: &[u8], password: &str) -> Vec<u8> {
        let mut encrypted = Vec::new();
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let mut hasher = Sha1::new();
        hasher.update(&salt);
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut rc4 = Rc4::new(&hash);
        let skip: Vec<u8> = vec![0; 0x300];
        let mut skip_out: Vec<u8> = vec![0; 0x300];
        rc4.process(&skip, &mut skip_out);
        encrypted.append(&mut MAGIC_ENCRYPTED_RC4.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 8).try_into().unwrap();
        encrypted.append(&mut content_len.to_le_bytes().to_vec());
        encrypted.append(&mut salt.to_vec());
        let mut output: Vec<u8> = vec![0; 4];
        rc4.process(&MAGIC_PLAINTEXT.to_le_bytes(), &mut output);
        encrypted.append(&mut output);
        let mut temp: Vec<u8> = vec![0; content_len as usize];
        rc4.process(&file_content[8..], &mut temp);
        encrypted.append(&mut temp);
        encrypted
    }
}

/// AES encrypted file type
#[derive(BinRead, PartialEq, Debug)]
pub struct AESFile {
    /// Common header
    pub header: Header,
    /// Encryption salt
    #[br(count = 32)]
    pub salt: Vec<u8>,
    // offset 40
    /// Signature for hmac
    #[br(count = 32)]
    pub signature: Vec<u8>,
    /// Magic to check if the decryption is correct
    pub magic_check: u32,
}

impl AESFile {
    /// Check if the AES file password is correct or not
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
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    /// Decrypt the AES file
    pub fn decrypt(&self, file_content: &[u8], password: &str) -> Result<Vec<u8>, Vec<u8>> {
        let mut decrypted = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let finalized = hasher.finalize();
        let hash = &finalized[0..16];
        let hash_hmac = &finalized[16..];
        let mut hmac = HmacSha256::new_from_slice(hash_hmac).expect("failed to create HmacSha256");
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
        hmac.update(&self.magic_check.to_le_bytes());
        hmac.update(to_decrypt);
        match hmac.verify_slice(&self.signature) {
            Ok(_) => Ok(decrypted),
            Err(_) => Err(decrypted),
        }
    }

    /// Encrypt the file to AES type
    pub fn encrypt(file_content: &[u8], password: &str) -> Vec<u8> {
        let mut encrypted = Vec::new();
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        encrypted.append(&mut MAGIC_ENCRYPTED_AES.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 8).try_into().unwrap();
        encrypted.append(&mut content_len.to_le_bytes().to_vec());
        encrypted.append(&mut salt.clone().to_vec());
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(password.as_bytes());
        let finalized = hasher.finalize();
        let hash = &finalized[0..16];
        let hash_hmac = &finalized[16..];
        let mut hmac = HmacSha256::new_from_slice(hash_hmac).expect("failed to create HmacSha256");
        let mut aes_ctr = aes::ctr(KeySize::KeySize128, hash, &salt[0..16]);
        let skip: Vec<u8> = vec![0; 0x10];
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.process(&skip, &mut skip_out);
        let mut output: Vec<u8> = vec![0; 4];
        aes_ctr.process(&MAGIC_PLAINTEXT.to_le_bytes(), &mut output);
        hmac.update(&output);
        let mut temp: Vec<u8> = vec![0; content_len as usize];
        aes_ctr.process(&file_content[8..], &mut temp);
        hmac.update(&temp);
        let into_bytes = hmac.finalize().into_bytes();
        encrypted.append(&mut into_bytes.as_slice().to_vec());
        encrypted.append(&mut output);
        encrypted.append(&mut temp);
        encrypted
    }
}

#[derive(BinRead, PartialEq, Debug, BinWrite)]
#[binwrite(little)]
struct PackedItem {
    len: u32,
    #[br(count = len)]
    content: Vec<u8>,
}

#[derive(BinRead, PartialEq, Debug, BinWrite)]
#[binwrite(little)]
struct PackedTriple {
    name: PackedItem,
    idx: PackedItem,
    dat: PackedItem,
}

/// Structure representing a packed file, with a name, idx and dat
#[derive(PartialEq, Debug)]
pub struct PackedFile {
    /// Filename
    pub name: String,
    /// idx file content
    pub idx: Vec<u8>,
    /// dat file content
    pub dat: Vec<u8>,
}

/// Plaintext unencrypted file
#[derive(BinRead, PartialEq, Debug)]
pub struct PlainTextFile {
    /// Common header
    pub header: Header,
}

impl PlainTextFile {
    /// Unpack a decrypted file
    pub fn unpack_files(&self, file_content: &[u8]) -> Vec<PackedFile> {
        let mut files: Vec<PackedFile> = Vec::new();
        let file_content = &file_content[8..];
        let mut extracted: Vec<PackedTriple> = Vec::new();
        let mut cursor = Cursor::new(file_content);
        loop {
            let r: BinResult<PackedTriple> = cursor.read_le();
            if r.is_err() {
                break;
            }
            let e = r.unwrap();
            extracted.push(e);
        }
        for c in extracted.iter() {
            files.push(PackedFile {
                name: str::from_utf8(&c.name.content).unwrap().to_string(),
                idx: c.idx.content.clone(),
                dat: c.dat.content.clone(),
            });
        }
        files
    }

    /// Pack files to a decrypted file
    pub fn pack_files(files: &[PackedFile]) -> Vec<u8> {
        let mut packed: Vec<u8> = Vec::new();
        for f in files.iter() {
            let name_vec: Vec<u8> = f.name.clone().into_bytes();
            let t = PackedTriple {
                name: PackedItem {
                    len: (name_vec.len() as u32),
                    content: name_vec,
                },
                idx: PackedItem {
                    len: f.idx.len() as u32,
                    content: f.idx.clone(),
                },
                dat: PackedItem {
                    len: f.dat.len() as u32,
                    content: f.dat.clone(),
                },
            };
            let mut tmp: Vec<u8> = Vec::new();
            t.write(&mut tmp).unwrap();
            packed.append(&mut tmp);
        }
        let content_len: u32 = (packed.len() - 4) as u32;
        let mut header: Vec<u8> = Vec::new();
        header.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        header.append(&mut content_len.to_le_bytes().to_vec());
        header.append(&mut packed);
        header
    }
}

/// Enum of all the possible RouterOS filetypes
#[derive(PartialEq, Debug)]
pub enum WholeFile {
    /// RC4 Encrypted type
    RC4File(RC4File),
    /// AES encrypted type
    AESFile(AESFile),
    /// Unencrypted type
    PlainTextFile(PlainTextFile),
    /// The file is not valid
    InvalidFile,
}

impl WholeFile {
    /// Parse raw bytes into one of the file types
    pub fn parse(raw: &[u8]) -> WholeFile {
        let h: Header = Header::parse(raw);
        match h.magic {
            MAGIC_ENCRYPTED_RC4 => WholeFile::RC4File(Cursor::new(raw).read_le().unwrap()),
            MAGIC_ENCRYPTED_AES => WholeFile::AESFile(Cursor::new(raw).read_le().unwrap()),
            MAGIC_PLAINTEXT => WholeFile::PlainTextFile(Cursor::new(raw).read_le().unwrap()),
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
            assert_eq!(
                decrypted_content,
                f.decrypt(&file_content, "aespass").unwrap()
            );
        } else {
            panic!("We didn't get a AESFile");
        }
    }

    #[test]
    fn check_rc4_encryption() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        let encrypted = RC4File::encrypt(&decrypted_content, "rc4pass");
        if let WholeFile::RC4File(f) = WholeFile::parse(&encrypted) {
            assert_eq!(decrypted_content, f.decrypt(&encrypted, "rc4pass"));
        } else {
            panic!("We didn't get a RC4File");
        }
    }

    #[test]
    fn check_aes_encryption() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        let encrypted = AESFile::encrypt(&decrypted_content, "aespass");
        if let WholeFile::AESFile(f) = WholeFile::parse(&encrypted) {
            assert_eq!(decrypted_content, f.decrypt(&encrypted, "aespass").unwrap());
        } else {
            panic!("We didn't get a AESFile");
        }
    }

    #[test]
    fn check_unpack_files() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        match WholeFile::parse(&decrypted_content) {
            WholeFile::PlainTextFile(f) => {
                let unpacked = f.unpack_files(&decrypted_content);
                assert_eq!(0, unpacked.len());
            }
            _ => {
                panic!("we didn't get a PlainTextFile");
            }
        }
    }

    #[test]
    fn check_pack_unpack() {
        let mut files: Vec<PackedFile> = Vec::new();
        files.push(PackedFile {
            name: "test1".to_string(),
            idx: vec![1; 5],
            dat: vec![2; 4],
        });
        files.push(PackedFile {
            name: "test2".to_string(),
            idx: vec![3; 7],
            dat: vec![4; 8],
        });
        let packed = PlainTextFile::pack_files(&files);
        match WholeFile::parse(&packed) {
            WholeFile::PlainTextFile(f) => {
                let unpacked = f.unpack_files(&packed);
                assert_eq!(files, unpacked);
            }
            _ => {
                panic!("we didn't get a PlainTextFile");
            }
        }
    }
}

/// utility to read a file in a vector of bytes
pub fn read_file_to_bytes(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

/// Utility to write a vector of bytes to a file
pub fn write_bytes_to_file(content: &[u8], filename: &str) -> std::io::Result<()> {
    let mut file = File::open(filename)?;
    file.write_all(content)?;
    Ok(())
}

/// Utility to read the wordlist for password cracking to a vec of strings
pub fn read_wordlist_file(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let buf = BufReader::new(file);
    Ok(buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>())
}
