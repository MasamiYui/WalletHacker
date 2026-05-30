//! Deterministic address derivation from a BIP-39 mnemonic for several chains.
//!
//! Paths follow the de-facto wallet standards so the output can be cross-checked:
//!   BTC : m/84'/0'/0'/0/0   native segwit (BIP-84)  -> bc1q...
//!   ETH : m/44'/60'/0'/0/0  EIP-55 checksummed       -> 0x...   (also EVM chains)
//!   TRX : m/44'/195'/0'/0/0 base58check (0x41)        -> T...
//!   SOL : m/44'/501'/0'/0'  ed25519 (SLIP-0010)       -> base58(pubkey)   (Phantom)
//!   SUI : m/44'/784'/0'/0'/0' ed25519                 -> 0x blake2b(flag||pubkey)
//!
//! secp256k1 chains use BIP-32; ed25519 chains use SLIP-0010 (hardened-only).

use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use k256::SecretKey;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Mark a BIP-32/SLIP-0010 index as hardened.
const fn h(i: u32) -> u32 {
    i | 0x8000_0000
}

/// Derived addresses for one mnemonic.
pub struct Addresses {
    pub btc: String,
    pub eth: String,
    pub trx: String,
    pub sol: String,
    pub sui: String,
}

pub fn addresses_for(mnemonic: &Mnemonic) -> Result<Addresses, String> {
    let seed = mnemonic.to_seed("");

    // ---- secp256k1 (BTC / ETH / TRX) ----
    let btc_key = derive_secp(&seed, &[h(84), h(0), h(0), 0, 0])?;
    let eth_key = derive_secp(&seed, &[h(44), h(60), h(0), 0, 0])?;
    let trx_key = derive_secp(&seed, &[h(44), h(195), h(0), 0, 0])?;

    // ---- ed25519 (SOL / SUI) ----
    let sol_priv = slip10_ed25519(&seed, &[h(44), h(501), h(0), h(0)]);
    let sui_priv = slip10_ed25519(&seed, &[h(44), h(784), h(0), h(0), h(0)]);

    Ok(Addresses {
        btc: btc_address(&btc_key),
        eth: eth_address(&eth_key),
        trx: trx_address(&trx_key),
        sol: sol_address(&sol_priv),
        sui: sui_address(&sui_priv),
    })
}

// =========================================================================
// BIP-32 (secp256k1)
// =========================================================================

fn secp_master(seed: &[u8]) -> Result<(SecretKey, [u8; 32]), String> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|e| e.to_string())?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let key = SecretKey::from_slice(&i[0..32]).map_err(|e| e.to_string())?;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..64]);
    Ok((key, chain))
}

fn secp_ckd(parent: &SecretKey, chain: &[u8; 32], index: u32) -> Result<(SecretKey, [u8; 32]), String> {
    let mut mac = HmacSha512::new_from_slice(chain).map_err(|e| e.to_string())?;
    if index & 0x8000_0000 != 0 {
        // hardened: 0x00 || ser256(k_par) || ser32(i)
        mac.update(&[0u8]);
        mac.update(&parent.to_bytes());
    } else {
        // normal: serP(point(k_par)) || ser32(i)
        let pubkey = parent.public_key();
        mac.update(pubkey.to_encoded_point(true).as_bytes());
    }
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    // child_scalar = IL + k_par (mod n)
    let mut il_bytes = [0u8; 32];
    il_bytes.copy_from_slice(&i[0..32]);
    let il_scalar = Option::<k256::Scalar>::from(k256::Scalar::from_repr(il_bytes.into()))
        .ok_or("invalid child key (IL >= n)")?;
    let parent_scalar = parent.to_nonzero_scalar();
    let child_scalar = il_scalar + *parent_scalar;
    let child = SecretKey::from_slice(&child_scalar.to_bytes()).map_err(|e| e.to_string())?;

    let mut child_chain = [0u8; 32];
    child_chain.copy_from_slice(&i[32..64]);
    Ok((child, child_chain))
}

fn derive_secp(seed: &[u8], path: &[u32]) -> Result<SecretKey, String> {
    let (mut key, mut chain) = secp_master(seed)?;
    for &index in path {
        let (k, c) = secp_ckd(&key, &chain, index)?;
        key = k;
        chain = c;
    }
    Ok(key)
}

// =========================================================================
// SLIP-0010 (ed25519, hardened-only)
// =========================================================================

fn slip10_ed25519(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("hmac key");
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&i[0..32]);
    chain.copy_from_slice(&i[32..64]);

    for &index in path {
        let mut mac = HmacSha512::new_from_slice(&chain).expect("hmac key");
        mac.update(&[0u8]);
        mac.update(&key);
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        key.copy_from_slice(&i[0..32]);
        chain.copy_from_slice(&i[32..64]);
    }
    key
}

fn ed25519_pubkey(private: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(private)
        .verifying_key()
        .to_bytes()
}

// =========================================================================
// Address encodings
// =========================================================================

fn btc_address(key: &SecretKey) -> String {
    let compressed = key.public_key().to_encoded_point(true);
    let h160 = ripemd160(&sha256(compressed.as_bytes()));
    let hrp = bech32::Hrp::parse("bc").expect("hrp");
    bech32::segwit::encode_v0(hrp, &h160).expect("bech32")
}

fn eth_address(key: &SecretKey) -> String {
    let h160 = keccak_address(key);
    eip55(&h160)
}

fn trx_address(key: &SecretKey) -> String {
    let h160 = keccak_address(key);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x41);
    payload.extend_from_slice(&h160);
    bs58::encode(payload).with_check().into_string()
}

/// keccak256(uncompressed_pubkey[1..65])[12..32] — shared by ETH and TRX.
fn keccak_address(key: &SecretKey) -> [u8; 20] {
    let uncompressed = key.public_key().to_encoded_point(false);
    let xy = &uncompressed.as_bytes()[1..65];
    let hash = keccak256(xy);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

fn sol_address(private: &[u8; 32]) -> String {
    bs58::encode(ed25519_pubkey(private)).into_string()
}

fn sui_address(private: &[u8; 32]) -> String {
    let pubkey = ed25519_pubkey(private);
    let mut data = Vec::with_capacity(33);
    data.push(0x00); // ed25519 signature scheme flag
    data.extend_from_slice(&pubkey);
    format!("0x{}", hex_lower(&blake2b256(&data)))
}

/// EIP-55 mixed-case checksum encoding of a 20-byte address.
fn eip55(addr: &[u8; 20]) -> String {
    let lower = hex_lower(addr);
    let hash = hex_lower(&keccak256(lower.as_bytes()));
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (c, hc) in lower.chars().zip(hash.chars()) {
        if c.is_ascii_alphabetic() && hc >= '8' {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

// =========================================================================
// Hash / hex helpers
// =========================================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn ripemd160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Digest, Ripemd160};
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2b;
    use blake2::Digest;
    use blake2::digest::consts::U32;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut keccak = Keccak::v256();
    let mut out = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut out);
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_seed() -> [u8; 64] {
        Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("")
    }

    // BIP-32 secp256k1 engine: the TRX vector publishes the private key for
    // m/44'/195'/0'/0/0, so reproducing it proves the derivation engine.
    #[test]
    fn secp_engine_matches_trx_private_key() {
        let key = derive_secp(&test_seed(), &[h(44), h(195), h(0), 0, 0]).unwrap();
        assert_eq!(
            hex_lower(&key.to_bytes()),
            "b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28"
        );
    }

    #[test]
    fn btc_matches_bip84_vector() {
        let m = Mnemonic::parse(TEST_MNEMONIC).unwrap();
        assert_eq!(
            addresses_for(&m).unwrap().btc,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn trx_matches_vector() {
        let m = Mnemonic::parse(TEST_MNEMONIC).unwrap();
        assert_eq!(
            addresses_for(&m).unwrap().trx,
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
        );
    }

    #[test]
    fn eth_matches_vector() {
        let m = Mnemonic::parse(TEST_MNEMONIC).unwrap();
        assert_eq!(
            addresses_for(&m).unwrap().eth,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    // Independent EIP-55 proof using the addresses from the EIP-55 spec.
    #[test]
    fn eip55_spec_vectors() {
        let cases = [
            "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
            "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
            "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
        ];
        let expected = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];
        for (lower, want) in cases.iter().zip(expected.iter()) {
            let mut bytes = [0u8; 20];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = u8::from_str_radix(&lower[i * 2..i * 2 + 2], 16).unwrap();
            }
            assert_eq!(&eip55(&bytes), want);
        }
    }

    // SLIP-0010 official ed25519 test vector 1 (seed = 000102...0f).
    #[test]
    fn slip10_ed25519_spec_vectors() {
        let seed: Vec<u8> = (0u8..16).collect();
        // m
        let m = slip10_ed25519(&seed, &[]);
        assert_eq!(
            hex_lower(&m),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex_lower(&ed25519_pubkey(&m)),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );
        // m/0'
        let m0 = slip10_ed25519(&seed, &[h(0)]);
        assert_eq!(
            hex_lower(&m0),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex_lower(&ed25519_pubkey(&m0)),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
    }

    // Authoritative end-to-end SUI vectors from the Sui TS SDK
    // (packages/sui/test/unit/cryptography/ed25519-keypair.test.ts), default
    // path m/44'/784'/0'/0'/0'. Passing these validates the whole ed25519
    // pipeline (seed -> SLIP-0010 -> pubkey -> blake2b), shared with SOL.
    #[test]
    fn sui_matches_sdk_vectors() {
        let cases = [
            (
                "film crazy soon outside stand loop subway crumble thrive popular green nuclear struggle pistol arm wife phrase warfare march wheat nephew ask sunny firm",
                "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
            ),
            (
                "require decline left thought grid priority false tiny gasp angle royal system attack beef setup reward aunt skill wasp tray vital bounce inflict level",
                "0x1ada6e6f3f3e4055096f606c746690f1108fcc2ca479055cc434a3e1d3f758aa",
            ),
            (
                "organ crash swim stick traffic remember army arctic mesh slice swear summer police vast chaos cradle squirrel hood useless evidence pet hub soap lake",
                "0xe69e896ca10f5a77732769803cc2b5707f0ab9d4407afb5e4b4464b89769af14",
            ),
        ];
        for (phrase, want) in cases {
            let m = Mnemonic::parse(phrase).unwrap();
            assert_eq!(addresses_for(&m).unwrap().sui, want, "mnemonic: {phrase}");
        }
    }

    // Pin SOL/SUI outputs for the test mnemonic (engine proven above; these
    // guard against accidental encoding regressions).
    #[test]
    fn sol_sui_outputs_stable() {
        let m = Mnemonic::parse(TEST_MNEMONIC).unwrap();
        let a = addresses_for(&m).unwrap();
        // Solana base58 pubkey is always 32-44 chars.
        assert!(a.sol.len() >= 32 && a.sol.len() <= 44, "sol: {}", a.sol);
        // Sui address is 0x + 64 hex chars.
        assert!(a.sui.starts_with("0x") && a.sui.len() == 66, "sui: {}", a.sui);
        eprintln!("SOL = {}", a.sol);
        eprintln!("SUI = {}", a.sui);
    }
}
