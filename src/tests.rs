#[cfg(test)]
mod testz {
    use crate::{
        AESFile, Header, PackedFile, PlainTextFile, RC4File, WholeFile, MAGIC_ENCRYPTED_AES,
        MAGIC_ENCRYPTED_RC4, MAGIC_PLAINTEXT,
    };
    #[test]
    fn parse_header() {
        let file_content: Vec<u8> = vec![0x34, 0x12, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00];
        assert_eq!(
            Header::parse(&file_content).expect("cannot parse header"),
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
        let mut magic_check: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44];
        file_content.append(&mut magic_check);
        assert_eq!(
            WholeFile::parse(&file_content).expect("cannot parse file"),
            WholeFile::RC4File(RC4File {
                header: Header {
                    magic: MAGIC_ENCRYPTED_RC4,
                    length: 0x5678
                },
                salt,
                magic_check: 0x4443_4241,
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
        let mut magic_check: Vec<u8> = vec![0x51, 0x52, 0x53, 0x54];
        file_content.append(&mut magic_check);
        assert_eq!(
            WholeFile::parse(&file_content).expect("cannot parse file"),
            WholeFile::AESFile(AESFile {
                header: Header {
                    magic: MAGIC_ENCRYPTED_AES,
                    length: 0x5678
                },
                salt,
                signature,
                magic_check: 0x5453_5251,
            })
        );
    }

    #[test]
    fn parse_plaintext_file() {
        let file_content: Vec<u8> = vec![0x88, 0xAC, 0xA1, 0xB1, 0x78, 0x56, 0x00, 0x00];
        assert_eq!(
            WholeFile::parse(&file_content).expect("cannot parse file"),
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
        if let WholeFile::RC4File(f) = WholeFile::parse(&file_content).expect("cannot parse file") {
            assert!(f.check_password("modificailrouter"));
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
        if let WholeFile::AESFile(f) = WholeFile::parse(&file_content).expect("cannot parse file") {
            assert!(f.check_password("aespass"));
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
        if let WholeFile::RC4File(f) = WholeFile::parse(&file_content).expect("cannot parse file") {
            assert_eq!(
                decrypted_content,
                f.decrypt(&file_content, "modificailrouter")
                    .expect("cannot decrypt")
                    .as_vec()
                    .clone()
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
        if let WholeFile::AESFile(f) = WholeFile::parse(&file_content).expect("cannot parse file") {
            assert_eq!(
                decrypted_content,
                f.decrypt(&file_content, "aespass")
                    .expect("cannot decrypt")
                    .as_vec()
                    .clone()
            );
        } else {
            panic!("We didn't get a AESFile");
        }
    }

    #[test]
    fn check_rc4_encryption() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        let encrypted = RC4File::encrypt(&decrypted_content, "rc4pass").expect("cannot encrypt");
        if let WholeFile::RC4File(f) = WholeFile::parse(&encrypted).expect("cannot parse file") {
            assert_eq!(
                decrypted_content,
                f.decrypt(&encrypted, "rc4pass")
                    .expect("cannot decrypt")
                    .as_vec()
                    .clone()
            );
        } else {
            panic!("We didn't get a RC4File");
        }
    }

    #[test]
    fn check_aes_encryption() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        let encrypted = AESFile::encrypt(&decrypted_content, "aespass").expect("cannot encrypt");
        if let WholeFile::AESFile(f) = WholeFile::parse(&encrypted).expect("cannot parse file") {
            assert_eq!(
                decrypted_content,
                f.decrypt(&encrypted, "aespass")
                    .expect("cannot decrypt")
                    .as_vec()
                    .clone()
            );
        } else {
            panic!("We didn't get a AESFile");
        }
    }

    #[test]
    fn check_unpack_files() {
        let decrypted_content: Vec<u8> = vec![0x88, 0xac, 0xa1, 0xb1, 0x08, 0x00, 0x00, 0x00];
        match WholeFile::parse(&decrypted_content).expect("cannot parse file") {
            WholeFile::PlainTextFile(f) => {
                let unpacked = f
                    .unpack_files(&decrypted_content)
                    .expect("cannot unpack files");
                assert_eq!(0, unpacked.len());
            }
            _ => {
                panic!("we didn't get a PlainTextFile");
            }
        }
    }

    #[test]
    fn check_pack_unpack() {
        let files: Vec<PackedFile> = vec![
            PackedFile {
                name: "test1".to_string(),
                idx: vec![1; 5],
                dat: vec![2; 4],
            },
            PackedFile {
                name: "test2".to_string(),
                idx: vec![3; 7],
                dat: vec![4; 8],
            },
        ];
        let packed = PlainTextFile::pack_files(&files).expect("cannot pack");
        match WholeFile::parse(&packed).expect("cannot parse file") {
            WholeFile::PlainTextFile(f) => {
                let unpacked = f.unpack_files(&packed).expect("cannot unpack files");
                assert_eq!(files, unpacked);
            }
            _ => {
                panic!("we didn't get a PlainTextFile");
            }
        }
    }
}
