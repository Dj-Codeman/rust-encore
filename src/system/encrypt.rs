use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use hex;
use hmac::{Hmac, Mac};
use substring::Substring;
use sha2::{Sha256, Digest};
use rand::{distributions::Alphanumeric, Rng};
use std::str;

// my junk
use crate::{
system::{halt, truncate, warn }, 
functions::fetch_key_data
};

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[allow(dead_code)]
pub fn create_key() -> String {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    return key;
}

#[allow(dead_code)]
fn create_iv() -> String {
    // Generating initial vector
    let initial_vector: String = rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(16)
    .map(char::from)
    .collect();

    // legacy junk from porting 
    if initial_vector.len() <= 15 && initial_vector.len() >= 17 {
        warn("Initial vector might be wrong");
    }

    return initial_vector;
}

#[allow(dead_code)]
pub fn create_hash(data: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    return hex::encode(result);
    // 256 because its responsible for generating the writing keys
}

pub fn encrypt(data: String, key: String) -> String {
    let iv = create_iv();
    let plain_text = data.as_bytes();
    let key = key.as_bytes();

    let cipher = Aes256Cbc::new_from_slices(&key, iv.as_bytes()).unwrap();
    let pad_len = plain_text.len();

    // max array data size technically the max file size to write
    // current limit: ~825Mb  capacity 1,073,741,824 bytes * 
    // 1728733184
    // 1073741824
    let mut buffer: Vec<u8> = vec![0; 1*1024*1024*1024];

    buffer[..pad_len].copy_from_slice(plain_text);

    let ciphertext = hex::encode(cipher.encrypt(&mut buffer, pad_len).unwrap());

    let mut cipherdata = String::new();

    cipherdata.push_str(&ciphertext);
    cipherdata.push_str(&iv);
    
    // creating hmac
    let hmac = create_hmac(cipherdata.clone());

    cipherdata.push_str(&hmac);

    return cipherdata;
}

pub fn decrypt(cipherdata: String, key: String) -> String {
    let cipherdata = cipherdata.clone();
    //cipherdata legnth minus the hmac because its appened later
    let cipherdata_len: usize = cipherdata.len() - 64;

    // warn(&String::from(cipherdata_len.to_string()));
    // dump(&cipherdata);

    // removed the hmac from the cipher string to generate the new hmac 
    let cipherdata_hmacless: String = truncate( &cipherdata, cipherdata_len).to_string();

    // getting old and new hmac values
    let old_hmac = cipherdata.substring(cipherdata_len, cipherdata_len+64);
    let new_hmac: String = create_hmac(cipherdata_hmacless.clone());

    // verifing hmac

    if old_hmac == new_hmac {
        // pulling the iv 
        let initial_vector: &str = cipherdata.substring(cipherdata_len-16, cipherdata_len);
        // define new cipher for decrypting
        let cipher = Aes256Cbc::new_from_slices(key.as_bytes(), initial_vector.as_bytes());
        // get the cipher text from the data bundle 
        let encoded_ciphertext = truncate(&cipherdata, cipherdata_len-16);
        // undo the hexencoding result
        let decoded_ciphertext = hex::decode(encoded_ciphertext).unwrap();
        // turn the data to a VEC byte array and decrypt it
        let mut buf = decoded_ciphertext.to_vec();
        // decrypt the binary data
        let decrypted_ciphertext = cipher.expect("Couldn't decrypt text").decrypt(&mut buf).unwrap();
        // turn it back into text 
        return str::from_utf8(decrypted_ciphertext).unwrap().to_string();

    } else {
        // Breaking because the hmac isn't valid
        halt("INVALID HMAC. TAMPERING DETECTED");
        return "".to_string();
    }
}

fn create_hmac(cipherdata: String) -> String {
    // create hmac
    // make alias
    type HmacSha256 = Hmac<Sha256>;

    // when the hmac is verified we check aginst the systemkey
    let mut mac = HmacSha256::new_from_slice(fetch_key_data("systemkey".to_string()).as_bytes())
    .expect("HMAC can take key of any size");

    mac.update(cipherdata.as_bytes());
    let hmac = hex::encode(mac.finalize().into_bytes());

    if hmac.len() >= 65 {
        halt("Invalid hmac generated");
    } else if hmac.len() <= 63 {
        halt("HMAC TO SMALL");
    }

    return hmac;
}

// 42c9446f850b783a5cbe8f9681f495b6680766476d2dca5ab28aa45db4480f71 < HMAC
// OpnB7QriBsNtG75d < IV
// DATA > ef8813edde20709ba95e0a44ef73597a IV> OpnB7QriBsNtG75d HMAC> 42c9446f850b783a5cbe8f9681f495b6680766476d2dca5ab28aa45db4480f71
// ef8813edde20709ba95e0a44ef73597aOpnB7QriBsNtG75d42c9446f850b783a5cbe8f9681f495b6680766476d2dca5ab28aa45db4480f71
// e00d8e2016020cf48a7042df0f3e0c2d1dcecfb45f9897371f0f513d832fd525

// DATA> c9fb78a4b091036d59d7cfdf81f1b7d36cf85cc525f741e833739521d4b94ac1 IV> jRNL5vhxohMOxMIGe HMAC> 7c4189bb8c7966c83050e5e16ebdf5e5f6b5672c3d9b89e855700306b0ea4c0
// 7c4189bb8c7966c83050e5e16ebdf5e5f6b5672c3d9b89e855700306b0ea4c0
// b935dadddfec74c0de39d45cbe87b3f2ad48ad8df8eddbe0dd55cfc7e6a9aa87!