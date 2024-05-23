//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

fn main() {}

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::{thread_rng, Rng};
use std::{sync::mpsc, thread::spawn};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When we have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn ungroup(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut output = Vec::new();
    blocks.iter().for_each(|block| output.extend(block));
    output
}

/// Does the opposite of the pad function.
fn unpad(data: Vec<u8>) -> Vec<u8> {
    let len = data.len();
    let where_to_cut = len - data[len - 1] as usize;
    data.split_at(where_to_cut).0.to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let mut handles = Vec::new();
    let (tx, rx) = mpsc::channel();
    let padded_text = pad(plain_text); // Pad the plain_text to get a multiple of the block_size
    let blocks = group(padded_text); // Split the text in blocks
    let mut cipher_text = vec![0u8; blocks.len() * BLOCK_SIZE]; // We create an empty vec of 0's with the desired length as output, As each block comes from a single thread, the vec needs to be initialized

    // For each block we spawn a thread and send down the channel the ciphered block and its block number, so we can then place each block in the right place
    blocks.into_iter().enumerate().for_each(|(index, block)| {
        let tx1 = tx.clone();
        handles.push(spawn(move || {
            // ECB encrypt stuff
            let encrypted_block = aes_encrypt(block, &key);
            let _ = tx1.send((index, encrypted_block));
        }))
    });
    // Handle the concurrency
    for handle in handles {
        handle.join().unwrap();
    }

    // Receive all the blocks and place them in the cipher_text
    loop {
        match rx.try_recv() {
            Ok((index, encrypted_block)) => cipher_text
                [index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE]
                .copy_from_slice(&encrypted_block),
            Err(_) => break,
        }
    }
    cipher_text
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut handles = Vec::new();
    let (tx, rx) = mpsc::channel();
    let blocks = group(cipher_text);
    let mut plain_text = vec![0u8; blocks.len() * BLOCK_SIZE];

    blocks.into_iter().enumerate().for_each(|(index, block)| {
        let tx1 = tx.clone();
        handles.push(spawn(move || {
            // ECB decrypt stuff
            let plain_block = aes_decrypt(block, &key);
            let _ = tx1.send((index, plain_block));
        }))
    });
    for handle in handles {
        handle.join().unwrap();
    }
    loop {
        match rx.try_recv() {
            Ok((index, plain_block)) => plain_text[index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE]
                .copy_from_slice(&plain_block),
            Err(_) => break,
        }
    }
    // The received text contain a padded block!
    unpad(plain_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/encrypted_block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Compute the IV
    let mut iv = [0u8; BLOCK_SIZE];
    thread_rng().try_fill(&mut iv).unwrap();
    // Pad the text
    let padded = pad(plain_text);
    let mut cipher_text = Vec::from(iv); // The first block of the cipher text is the IV
    let blocks = group(padded); // Split the text in blocks
    let mut previous_block = iv; // Keep track of the previous block to cipher with CBC. The first ocurrence is IV
    blocks.into_iter().for_each(|block| {
        // CBC encrypt stuff
        let mut xored = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = previous_block[i] ^ block[i];
        }
        let encrypted_block = aes_encrypt(xored, &key);
        cipher_text.extend(encrypted_block);
        previous_block = encrypted_block; // Keep track of the block
    });
    cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Extract the IV
    let (iv, cipher_text) = cipher_text.split_at(BLOCK_SIZE);
    let iv = <[u8; BLOCK_SIZE]>::try_from(iv).unwrap(); // If the message doesn't even include the iv the cipher's incorrect

    let blocks = group(cipher_text.to_vec()); // Split the ciphertext into blocks

    let mut plain_text = Vec::new();
    let mut previous_block = iv; // Keep track of the previous block to decrypt

    blocks.into_iter().for_each(|block| {
        // CBC decrypt stuff
        let decrypted_block = aes_decrypt(block, &key);
        let mut xored = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = decrypted_block[i] ^ previous_block[i];
        }
        plain_text.extend(xored);
        previous_block = block; // Update the previous block
    });

    unpad(plain_text)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.

// This functions increase the counter inside the IV used in CTR
fn increase_ctr_iv(iv: &mut [u8; 16]) {
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&iv[8..16]);

    let mut value = u64::from_be_bytes(counter);
    // Increment the value
    value += 1;

    // Convert back to bytes
    let incremented_bytes = value.to_be_bytes();
    iv[8..16].copy_from_slice(&incremented_bytes);
}

fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Compute the nonce
    let mut nonce = [0u8; BLOCK_SIZE / 2];
    thread_rng().try_fill(&mut nonce).unwrap();
    // Create the IV : None | Counter
    let mut iv = [0u8; BLOCK_SIZE];
    iv[..8].copy_from_slice(&nonce);

    let mut handles = Vec::new();
    let (tx, rx) = mpsc::channel();
    let padded_text = pad(plain_text); // Pad the plain_text to get a multiple of the block_size
    let blocks = group(padded_text); // Split the text in blocks
    let mut cipher_text = vec![0u8; (blocks.len() + 1) * BLOCK_SIZE]; // We create an empty vec of 0's with the desired length. As each block comes from a single thread, the vec needs to be initialized
    cipher_text[..BLOCK_SIZE].copy_from_slice(&iv); // The first block is the IV

    // For each block we spawn a thread and send down the channel the ciphered block and its block number, so we can then place each block in the right place
    blocks.into_iter().enumerate().for_each(|(index, block)| {
        let tx1 = tx.clone();
        handles.push(spawn(move || {
            // CTR encrypt stuff
            let encrypted_iv = aes_encrypt(iv, &key);
            let mut encrypted_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                encrypted_block[i] = encrypted_iv[i] ^ block[i];
            }
            let _ = tx1.send((index, encrypted_block));
        }));
        increase_ctr_iv(&mut iv);
    });
    // Handle the concurrency
    for handle in handles {
        handle.join().unwrap();
    }

    // Receive all the blocks and place them in the cipher_text
    loop {
        match rx.try_recv() {
            Ok((index, encrypted_block)) => cipher_text
                [(index + 1) * BLOCK_SIZE..(index + 2) * BLOCK_SIZE]
                .copy_from_slice(&encrypted_block), // The first index corresponds to the IV, so we have to increase every index by 1
            Err(_) => break,
        }
    }
    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Extract the IV
    let (iv, cipher_text) = cipher_text.split_at(BLOCK_SIZE);
    let mut iv = <[u8; BLOCK_SIZE]>::try_from(iv).unwrap(); // If the message doesn't even include the iv the cipher's incorrect

    let blocks = group(cipher_text.to_vec()); // Split the ciphertext into blocks

    let mut handles = Vec::new();
    let (tx, rx) = mpsc::channel();
    let blocks = group(cipher_text.to_vec());
    let mut plain_text = vec![0u8; blocks.len() * BLOCK_SIZE];

    blocks.into_iter().enumerate().for_each(|(index, block)| {
        let tx1 = tx.clone();
        handles.push(spawn(move || {
            let encrypted_iv = aes_encrypt(iv, &key);
            let mut plain_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                plain_block[i] = encrypted_iv[i] ^ block[i];
            }
            let _ = tx1.send((index, plain_block));
        }));
        increase_ctr_iv(&mut iv);
    });
    for handle in handles {
        handle.join().unwrap();
    }
    loop {
        match rx.try_recv() {
            Ok((index, plain_block)) => plain_text[index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE]
                .copy_from_slice(&plain_block),
            Err(_) => break,
        }
    }
    // The received text contain a padded block!
    unpad(plain_text)
}

/// This function is not graded. It is just for collecting feedback.
/// On a scale from 0 - 100, with zero being extremely easy and 100 being extremely hard, how hard
/// did you find the exercises in this section?
pub fn how_hard_was_this_section() -> u8 {
    todo!()
}

/// This function is not graded. It is just for collecting feedback.
/// About how much time (in hours) did you spend on the exercises in this section?
pub fn how_many_hours_did_you_spend_on_this_section() -> f32 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
    ];

    #[test]
    fn ungroup_test() {
        let data: Vec<u8> = (0..48).collect();
        let grouped = group(data.clone());
        let ungrouped = ungroup(grouped);
        assert_eq!(data, ungrouped);
    }

    #[test]
    fn unpad_test() {
        // An exact multiple of block size
        let data: Vec<u8> = (0..48).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);

        // A non-exact multiple
        let data: Vec<u8> = (0..53).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);
    }

    #[test]
    fn ecb_encrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let encrypted = ecb_encrypt(plaintext, TEST_KEY);
        assert_eq!(
            "12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555".to_string(),
            hex::encode(encrypted)
        );
    }

    #[test]
    fn ecb_decrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext =
            hex::decode("12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555")
                .unwrap();
        assert_eq!(plaintext, ecb_decrypt(ciphertext, TEST_KEY))
    }

    #[test]
    fn cbc_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = cbc_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = cbc_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    fn increase_ctr_iv_test() {
        let mut iv = [0u8; 16];
        increase_ctr_iv(&mut iv);
        assert_eq!(iv, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn ctr_roundtrip_test() {
        // Because CRT uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ctr_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ctr_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = ctr_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }
}
