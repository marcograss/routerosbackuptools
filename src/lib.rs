#![warn(missing_docs)]
//! Tools to encrypt/decrypt and pack/unpack `RouterOS` v6.13+ backup files

use aes::cipher::KeyIvInit;
use binrw::{io::Cursor, BinRead, BinReaderExt, BinResult, BinWrite};
use hmac_sha256::HMAC;
use rand::Rng;
use rc4::KeyInit;
use rc4::{Rc4, StreamCipher};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader, ErrorKind, Read};
use std::path::Path;
use std::str;

use anyhow::{anyhow, Result};

mod tests;

const MAGIC_ENCRYPTED_RC4: u32 = 0x7291_A8EF;
const MAGIC_ENCRYPTED_AES: u32 = 0x7391_A8EF;
const MAGIC_PLAINTEXT: u32 = 0xB1A1_AC88;

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;

/// Common Header for the router files
#[derive(BinRead, PartialEq, Debug, Eq)]
pub struct Header {
    /// Magic to identify the filetype
    pub magic: u32,
    /// Length of the file
    pub length: u32,
}

impl Header {
    /// Parse a header from raw bytes
    ///
    /// # Errors
    /// Can return a error if cannot read the 8 header bytes
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Cursor::new(raw).read_le().map_err(|e| anyhow!(e))
    }
}

/// RC4 type of file, encrypted with the rc4
#[derive(BinRead, PartialEq, Debug, Eq)]
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
    #[must_use]
    pub fn check_password(&self, password: &str) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut rc4 = Rc4::new(&hash);
        let mut skip_out: Vec<u8> = vec![0; 0x300];
        rc4.apply_keystream(&mut skip_out);
        let mut output: Vec<u8> = self.magic_check.to_le_bytes().into();
        rc4.apply_keystream(&mut output);
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    /// Decrypt the rc4 file content
    ///
    /// # Errors
    /// Can error out for several reasons
    pub fn decrypt(&self, file_content: &[u8], password: &str) -> Result<DecryptionResult> {
        let mut decrypted = Vec::new();
        let mut hasher = Sha1::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut rc4 = Rc4::new(&hash);
        let mut skip_out: Vec<u8> = vec![0; 0x300];
        rc4.apply_keystream(&mut skip_out);
        let mut output: Vec<u8> = self.magic_check.to_le_bytes().into();
        rc4.apply_keystream(&mut output);
        let to_decrypt = &file_content[44..]; // skip magic, length, salt, magic_check
        decrypted.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 44 + 8).try_into()?;
        decrypted.append(&mut content_len.to_le_bytes().to_vec());
        let mut temp: Vec<u8> = to_decrypt.to_vec();
        rc4.apply_keystream(&mut temp);
        decrypted.append(&mut temp);
        Ok(DecryptionResult::Correct(decrypted))
    }

    /// Encrypt a file content to this rc4 format
    ///
    /// # Errors
    /// Can error out for several reasons
    pub fn encrypt(file_content: &[u8], password: &str) -> Result<Vec<u8>> {
        let mut encrypted = Vec::new();
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let mut hasher = Sha1::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut rc4 = Rc4::new(&hash);
        let mut skip_out: Vec<u8> = vec![0; 0x300];
        rc4.apply_keystream(&mut skip_out);
        encrypted.append(&mut MAGIC_ENCRYPTED_RC4.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 8).try_into()?;
        encrypted.append(&mut content_len.to_le_bytes().to_vec());
        encrypted.append(&mut salt.to_vec());
        let mut output: Vec<u8> = MAGIC_PLAINTEXT.to_le_bytes().into();
        rc4.apply_keystream(&mut output);
        encrypted.append(&mut output);
        let mut temp: Vec<u8> = file_content[8..].to_vec();
        rc4.apply_keystream(&mut temp);
        encrypted.append(&mut temp);
        Ok(encrypted)
    }
}

/// AES encrypted file type
#[derive(BinRead, PartialEq, Debug, Eq)]
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

/// Distinguish if decryption is successful and if the signature is wrong
pub enum DecryptionResult {
    /// The decryption was as expected
    Correct(Vec<u8>),
    /// The decryption succeded but the signature was wrong
    WrongSignature(Vec<u8>),
}

impl DecryptionResult {
    /// get back the underlying data Vec<u8>
    #[must_use]
    pub const fn as_vec(&self) -> &Vec<u8> {
        match self {
            Self::Correct(v) | Self::WrongSignature(v) => v,
        }
    }
}

impl AESFile {
    /// Check if the AES file password is correct or not
    #[must_use]
    pub fn check_password(&self, password: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let hash = &hasher.finalize()[0..16];
        let mut aes_ctr = Aes128Ctr128BE::new(hash.into(), self.salt[0..16].into());
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.apply_keystream(&mut skip_out);
        let mut output: Vec<u8> = self.magic_check.to_le_bytes().to_vec();
        aes_ctr.apply_keystream(&mut output);
        output == MAGIC_PLAINTEXT.to_le_bytes()
    }

    /// Decrypt the AES file
    ///
    /// # Errors
    /// it can error for arithmetic problems
    pub fn decrypt(&self, file_content: &[u8], password: &str) -> Result<DecryptionResult> {
        let mut decrypted = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let finalized = hasher.finalize();
        let hash = &finalized[0..16];
        let hash_hmac = &finalized[16..];
        let mut hmac = HMAC::new(hash_hmac);
        let mut aes_ctr = Aes128Ctr128BE::new(hash.into(), self.salt[0..16].into());
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.apply_keystream(&mut skip_out);
        let mut output: Vec<u8> = self.magic_check.to_le_bytes().to_vec();
        aes_ctr.apply_keystream(&mut output);
        let to_decrypt = &file_content[76..]; // skip magic, length, salt/nonce, hmac magic_check
        decrypted.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 76 + 8).try_into()?;
        decrypted.append(&mut content_len.to_le_bytes().to_vec());
        let mut temp: Vec<u8> = to_decrypt.to_vec();
        aes_ctr.apply_keystream(&mut temp);
        decrypted.append(&mut temp);
        hmac.update(self.magic_check.to_le_bytes());
        hmac.update(to_decrypt);
        let verified = hmac.finalize();
        if self.signature.len() == verified.len() && verified.to_vec() == self.signature {
            Ok(DecryptionResult::Correct(decrypted))
        } else {
            Ok(DecryptionResult::WrongSignature(decrypted))
        }
    }

    /// Encrypt the file to AES type
    ///
    /// # Errors
    /// it can errors due arithmetic problems
    pub fn encrypt(file_content: &[u8], password: &str) -> Result<Vec<u8>> {
        let mut encrypted = Vec::new();
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        encrypted.append(&mut MAGIC_ENCRYPTED_AES.to_le_bytes().to_vec());
        let content_len: u32 = (file_content.len() - 8).try_into()?;
        encrypted.append(&mut content_len.to_le_bytes().to_vec());
        encrypted.append(&mut salt.clone().to_vec());
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        let finalized = hasher.finalize();
        let hash = &finalized[0..16];
        let hash_hmac = &finalized[16..];
        let mut hmac = HMAC::new(hash_hmac);
        let mut aes_ctr = Aes128Ctr128BE::new(hash.into(), salt[0..16].into());
        let mut skip_out: Vec<u8> = vec![0; 0x10];
        aes_ctr.apply_keystream(&mut skip_out);
        let mut output: Vec<u8> = MAGIC_PLAINTEXT.to_le_bytes().into();
        aes_ctr.apply_keystream(&mut output);
        hmac.update(&output);
        let mut temp: Vec<u8> = file_content[8..].to_vec();
        aes_ctr.apply_keystream(&mut temp);
        hmac.update(&temp);
        let into_bytes = hmac.finalize();
        encrypted.append(&mut into_bytes.as_slice().to_vec());
        encrypted.append(&mut output);
        encrypted.append(&mut temp);
        Ok(encrypted)
    }
}

#[derive(BinRead, PartialEq, Debug, BinWrite, Eq)]
#[brw(little)]
struct PackedItem {
    len: u32,
    #[br(count = len)]
    content: Vec<u8>,
}

#[derive(BinRead, PartialEq, Debug, BinWrite, Eq)]
#[brw(little)]
struct PackedTriple {
    name: PackedItem,
    idx: PackedItem,
    dat: PackedItem,
}

/// Structure representing a packed file, with a name, idx and dat
#[derive(PartialEq, Debug, Eq)]
pub struct PackedFile {
    /// Filename
    pub name: String,
    /// idx file content
    pub idx: Vec<u8>,
    /// dat file content
    pub dat: Vec<u8>,
}

/// Plaintext unencrypted file
#[derive(BinRead, PartialEq, Debug, Eq)]
pub struct PlainTextFile {
    /// Common header
    pub header: Header,
}

impl PlainTextFile {
    /// Unpack a decrypted file
    ///
    /// # Errors
    /// it can error if the filenames are invalid
    pub fn unpack_files(&self, file_content: &[u8]) -> Result<Vec<PackedFile>> {
        let mut files: Vec<PackedFile> = Vec::new();
        let file_content = &file_content[8..];
        let mut extracted: Vec<PackedTriple> = Vec::new();
        let mut cursor = Cursor::new(file_content);
        loop {
            let r: BinResult<PackedTriple> = cursor.read_le();
            if r.is_err() {
                break;
            }
            let e = r?;
            extracted.push(e);
        }
        for c in &extracted {
            files.push(PackedFile {
                name: str::from_utf8(&c.name.content)?.to_string(),
                idx: c.idx.content.clone(),
                dat: c.dat.content.clone(),
            });
        }
        Ok(files)
    }

    /// Pack files to a decrypted file
    ///
    /// # Errors
    /// it can error out for several reasons related to file sizes
    pub fn pack_files(files: &[PackedFile]) -> Result<Vec<u8>> {
        let mut packed: Vec<u8> = Vec::new();
        for f in files {
            let name_vec: Vec<u8> = f.name.clone().into_bytes();
            let t = PackedTriple {
                name: PackedItem {
                    len: name_vec.len().try_into()?,
                    content: name_vec,
                },
                idx: PackedItem {
                    len: f.idx.len().try_into()?,
                    content: f.idx.clone(),
                },
                dat: PackedItem {
                    len: f.dat.len().try_into()?,
                    content: f.dat.clone(),
                },
            };
            let mut tmp = Cursor::new(Vec::new());
            t.write(&mut tmp)?;
            packed.append(tmp.get_mut());
        }
        let content_len: u32 = (packed.len() - 4).try_into()?;
        let mut header: Vec<u8> = Vec::new();
        header.append(&mut MAGIC_PLAINTEXT.to_le_bytes().to_vec());
        header.append(&mut content_len.to_le_bytes().to_vec());
        header.append(&mut packed);
        Ok(header)
    }
}

/// Enum of all the possible `RouterOS` filetypes
#[derive(PartialEq, Debug, Eq)]
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
    ///
    /// # Errors
    /// it can error out while reading the header or the file
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let h: Header = Header::parse(raw)?;
        Ok(match h.magic {
            MAGIC_ENCRYPTED_RC4 => Self::RC4File(Cursor::new(raw).read_le()?),
            MAGIC_ENCRYPTED_AES => Self::AESFile(Cursor::new(raw).read_le()?),
            MAGIC_PLAINTEXT => Self::PlainTextFile(Cursor::new(raw).read_le()?),
            _ => Self::InvalidFile,
        })
    }
}

/// utility to read a file in a vector of bytes
///
/// # Errors
/// can error out while reading the file
pub fn read_file_to_bytes(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

/// Utility to write a vector of bytes to a file
///
/// # Errors
/// Writing the file can error out
pub fn write_bytes_to_file(content: &[u8], filename: &str) -> std::io::Result<()> {
    let parent_dir = Path::new(filename);
    let parent_dir = parent_dir
        .parent()
        .ok_or_else(|| std::io::Error::new(ErrorKind::Other, "can't get parent folder"))?;
    std::fs::create_dir_all(parent_dir)?;
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}

/// Utility to read the wordlist for password cracking to a vec of strings
///
/// # Errors
/// reading the file can error out
/// # Panics
/// can panic if the wordlist file cannot be parsed
pub fn read_wordlist_file(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let buf = BufReader::new(file);
    Ok(buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>())
}
