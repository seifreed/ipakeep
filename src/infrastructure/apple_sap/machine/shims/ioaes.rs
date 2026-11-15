//! `IOAESAccelerator` emulation for the pinned `FairPlay` kext: the commerce
//! device-key handle is AES-128-CBC under an all-zero key.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use super::error::ShimError;

/// AES block size in bytes (also the IV size).
pub(super) const AES_BLOCK_SIZE: usize = 16;
/// Size of the `IOAESAccelerator` key descriptor.
pub(super) const KEY_DATA_SIZE: usize = 40;
/// Offset of the little-endian key handle inside the key descriptor.
const KEY_HANDLE_OFFSET: usize = 36;
/// Device-key handle used by the commerce `FairPlay` path.
const COMMERCE_AES_HANDLE: u32 = 0x89c;
/// `IOAESAccelerator` operation: encrypt.
const OPERATION_ENCRYPT: u32 = 0;
/// `IOAESAccelerator` operation: decrypt.
const OPERATION_DECRYPT: u32 = 1;

/// Output of one emulated accelerator request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IoAesOutput {
    /// Transformed data, same length as the input.
    pub(super) data: Vec<u8>,
    /// Chaining value for the next request (last ciphertext block).
    pub(super) next_iv: [u8; AES_BLOCK_SIZE],
}

/// Runs AES-128-CBC with the all-zero device key over whole blocks of `source`.
pub(super) fn emulate_ioaes(
    source: &[u8],
    iv: &[u8],
    operation: u32,
    key_data: &[u8],
) -> Result<IoAesOutput, ShimError> {
    let iv: [u8; AES_BLOCK_SIZE] = iv
        .try_into()
        .map_err(|_| ShimError::Invalid("invalid IOAES parameters"))?;
    if source.is_empty()
        || !source.len().is_multiple_of(AES_BLOCK_SIZE)
        || key_data.len() != KEY_DATA_SIZE
    {
        return Err(ShimError::Invalid("invalid IOAES parameters"));
    }
    let handle = key_handle(key_data);
    if handle != COMMERCE_AES_HANDLE {
        return Err(ShimError::Unsupported {
            what: "IOAES key handle",
            value: u64::from(handle),
        });
    }
    let cipher = Aes128::new(&GenericArray::from([0; AES_BLOCK_SIZE]));

    match operation {
        OPERATION_ENCRYPT => Ok(encrypt(&cipher, source, iv)),
        OPERATION_DECRYPT => Ok(decrypt(&cipher, source, iv)),
        other => Err(ShimError::Unsupported {
            what: "IOAES operation",
            value: u64::from(other),
        }),
    }
}

fn key_handle(key_data: &[u8]) -> u32 {
    let mut handle = [0; 4];
    handle.copy_from_slice(&key_data[KEY_HANDLE_OFFSET..KEY_DATA_SIZE]);

    u32::from_le_bytes(handle)
}

fn encrypt(cipher: &Aes128, source: &[u8], iv: [u8; AES_BLOCK_SIZE]) -> IoAesOutput {
    let mut data = Vec::with_capacity(source.len());
    let mut chain = iv;
    for block in source.chunks_exact(AES_BLOCK_SIZE) {
        let mut buffer = GenericArray::from(chain);
        for (byte, input) in buffer.iter_mut().zip(block) {
            *byte ^= input;
        }
        cipher.encrypt_block(&mut buffer);
        chain = buffer.into();
        data.extend_from_slice(&chain);
    }

    IoAesOutput {
        data,
        next_iv: chain,
    }
}

fn decrypt(cipher: &Aes128, source: &[u8], iv: [u8; AES_BLOCK_SIZE]) -> IoAesOutput {
    let mut data = Vec::with_capacity(source.len());
    let mut chain = iv;
    for block in source.chunks_exact(AES_BLOCK_SIZE) {
        let mut buffer = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut buffer);
        for (byte, previous) in buffer.iter_mut().zip(chain) {
            *byte ^= previous;
        }
        data.extend_from_slice(&buffer);
        chain.copy_from_slice(block);
    }

    IoAesOutput {
        data,
        next_iv: chain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commerce_key() -> Vec<u8> {
        let mut key = vec![0; KEY_DATA_SIZE];
        key[KEY_HANDLE_OFFSET..].copy_from_slice(&COMMERCE_AES_HANDLE.to_le_bytes());
        key
    }

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hex")
    }

    // Vectors produced with `openssl enc -aes-128-cbc -nopad -K 00..00 -iv <iv>`.
    const PLAIN: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const IV: &str = "f0e0d0c0b0a090807060504030201000";
    const CIPHER: &str = "7ed1d732f2e0f04816a194bec0af08c57237d1bb9cca9aa432d607d2f417a493";

    #[test]
    fn zero_key_block_matches_fips_known_answer() {
        let output =
            emulate_ioaes(&[0; 16], &[0; 16], OPERATION_ENCRYPT, &commerce_key()).expect("encrypt");
        assert_eq!(
            hex::encode(&output.data),
            "66e94bd4ef8a2c3b884cfa59ca342b2e"
        );
        assert_eq!(output.next_iv.to_vec(), output.data);
    }

    #[test]
    fn cbc_round_trips_against_openssl_vector() {
        let cipher = unhex(CIPHER);
        let encrypted = emulate_ioaes(
            &unhex(PLAIN),
            &unhex(IV),
            OPERATION_ENCRYPT,
            &commerce_key(),
        )
        .expect("encrypt");
        assert_eq!(encrypted.data, cipher);
        assert_eq!(encrypted.next_iv.to_vec(), cipher[16..]);

        let decrypted = emulate_ioaes(&cipher, &unhex(IV), OPERATION_DECRYPT, &commerce_key())
            .expect("decrypt");
        assert_eq!(decrypted.data, unhex(PLAIN));
        assert_eq!(decrypted.next_iv.to_vec(), cipher[16..]);
    }

    #[test]
    fn rejects_bad_shapes_handles_and_operations() {
        let key = commerce_key();
        assert!(emulate_ioaes(&[], &[0; 16], 0, &key).is_err());
        assert!(emulate_ioaes(&[0; 15], &[0; 16], 0, &key).is_err());
        assert!(emulate_ioaes(&[0; 16], &[0; 8], 0, &key).is_err());
        assert!(emulate_ioaes(&[0; 16], &[0; 16], 0, &key[..39]).is_err());
        assert!(matches!(
            emulate_ioaes(&[0; 16], &[0; 16], 2, &key),
            Err(ShimError::Unsupported { value: 2, .. })
        ));
        let mut other = key;
        other[KEY_HANDLE_OFFSET] = 0;
        assert!(matches!(
            emulate_ioaes(&[0; 16], &[0; 16], 0, &other),
            Err(ShimError::Unsupported { .. })
        ));
    }
}
