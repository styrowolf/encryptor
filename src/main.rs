use std::fs;

extern crate argon2rs;
extern crate blake3;
extern crate clap;
extern crate chacha20poly1305;
extern crate getrandom;
extern crate aes_gcm_siv;

use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};

fn main() {
    let application = clap::App::new("encryptor")
        .version("1.0")
        .about("Encrypts and decrypts files")
        .arg(clap::Arg::with_name("encrypt")
            .short("e")
            .long("encrypt")
            .value_name("FILE")
            .required_unless("decrypt")
            .requires("passphrase")
            .requires("output")
            .requires("algorithm")
            .number_of_values(1)
            .help("Encrypts files")
        )
        .arg(clap::Arg::with_name("decrypt")
            .short("d")
            .long("decrypt")
            .value_name("FILE")
            .required_unless("encrypt")
            .requires("passphrase")
            .requires("output")
            .requires("algorithm")
            .number_of_values(1)
            .help("Decrypts files")
        )
        .arg(clap::Arg::with_name("passphrase")
            .short("p")
            .long("passphrase")
            .value_name("passphrase")
            .required(true)
            .number_of_values(1)
            .help("Passphrase to derive key with Argon2i")
        )
        .arg(clap::Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("FILE")
            .required(true)
            .number_of_values(1)
            .help("File to be outputted")
        )
        .arg(clap::Arg::with_name("algorithm")
            .short("a")
            .long("algorithm")
            .value_name("ALGORITHM")
            .possible_values(&["aes", "xchacha"])
            .required(true)
            .number_of_values(1)
            .help("Algorithm to use: AES-256-GCM-SIV or XChaCha20-Poly1305")
        )
        .get_matches();

    if application.is_present("encrypt") {
        let output_file_name = application.value_of("output").expect("no filename to output");
        let input_file_name = application.value_of("encrypt").expect("no filename as input");
        let plaintext = fs::read(input_file_name).expect("input file error");
        let passphrase = application.value_of("passphrase").expect("no passphrase detected").as_bytes();

        let key = passphrase_to_key(passphrase, 32);

        let mut nonce = Vec::new();
        let mut ciphertext = Vec::new();

        if application.value_of("algorithm").expect("unknown algorithm") == "xchacha" {
            nonce = generate_nonce(24);
            ciphertext = XChaCha20Poly1305_encrypt(plaintext, key, nonce);
        } else if application.value_of("algorithm").expect("unknown algorithm") == "aes" {
            nonce = generate_nonce(12);
            ciphertext = AES_GCM_SIV_encrypt(plaintext, key, nonce);
        }

        let _ = fs::write(output_file_name, ciphertext);
        
    } else if application.is_present("decrypt") {
        let output_file_name = application.value_of("output").expect("no filename to output");
        let input_file_name = application.value_of("decrypt").expect("no filename as input");
        let ciphertext = fs::read(input_file_name).expect("input file error");
        let passphrase = application.value_of("passphrase").expect("no passphrase detected").as_bytes();

        let key = passphrase_to_key(passphrase, 32);
        let mut plaintext = Vec::new();

        if application.value_of("algorithm").expect("unknown algorithm") == "xchacha" {
            plaintext = XChaCha20Poly1305_decrypt(ciphertext, key);
        } else if application.value_of("algorithm").expect("unknown algorithm") == "aes" {
            plaintext = AES_GCM_SIV_decrypt(ciphertext, key);
        }
        
        let _ = fs::write(output_file_name, plaintext);

    }
}

//key derivation using Argon2i with BLAKE3 hash of passphrase as salt
fn passphrase_to_key(passphrase: &[u8], length: usize) -> Vec<u8> {
    //using the hash of the passphrase as salt
    let salt = *blake3::hash(&passphrase).as_bytes();
    //init vector to fill
    let mut key: Vec<u8> = vec![0; length];
    argon2rs::Argon2::default(argon2rs::Variant::Argon2i).hash(&mut key, passphrase, &salt, &[], & []);
    key
}

fn XChaCha20Poly1305_encrypt(plaintext: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>) -> Vec<u8> {
    let aead = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut ciphertext = aead.encrypt(XNonce::from_slice(&nonce), plaintext.as_slice()).expect("encryption error");
    ciphertext.extend_from_slice(&nonce);
    ciphertext
}
fn XChaCha20Poly1305_decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let aead = XChaCha20Poly1305::new(Key::from_slice(&key));

    //get nonce from the last 24 bytes of the ciphertext
    let nonce = ciphertext.get(ciphertext.len()-24..ciphertext.len()).expect("error in getting nonce");

    //remove the nonce from the ciphertext
    let mut nonceless_ciphertext = ciphertext.to_vec();
    nonceless_ciphertext.drain(ciphertext.len()-24..ciphertext.len());

    let plaintext = aead.decrypt(XNonce::from_slice(&nonce), nonceless_ciphertext.as_slice()).expect("decryption error");
    plaintext
}

//nonce from system CSPRNG
fn generate_nonce(length: usize) -> Vec<u8> {
    let mut nonce: Vec<u8> = vec![0; length];
    let _ = getrandom::getrandom(&mut nonce);
    nonce
}

//nonce from XOF(plaintext||key) where BLAKE3 is XOF
fn derive_nonce(plaintext: Vec<u8>, key: Vec<u8>, length: usize) -> Vec<u8> {
    let mut nonce: Vec<u8> = vec![0; length];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&plaintext);
    hasher.update(&key);
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut nonce);
    nonce
}

fn AES_GCM_SIV_encrypt(plaintext: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>) -> Vec<u8> {
    let aead = aes_gcm_siv::Aes256GcmSiv::new(Key::from_slice(&key));
    let mut ciphertext = aead.encrypt(aes_gcm_siv::aead::generic_array::GenericArray::from_slice(&nonce), plaintext.as_slice()).expect("encryption error");
    ciphertext.extend_from_slice(&nonce);
    ciphertext
}

fn AES_GCM_SIV_decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let aead = aes_gcm_siv::Aes256GcmSiv::new(Key::from_slice(&key));

    //get nonce from the last 12 bytes of the ciphertext
    let nonce = ciphertext.get(ciphertext.len()-12..ciphertext.len()).expect("error in getting nonce");

    //remove the nonce from the ciphertext
    let mut nonceless_ciphertext = ciphertext.to_vec();
    nonceless_ciphertext.drain(ciphertext.len()-12..ciphertext.len());

    let plaintext = aead.decrypt(aes_gcm_siv::aead::generic_array::GenericArray::from_slice(&nonce), nonceless_ciphertext.as_slice()).expect("decryption error");
    plaintext
}