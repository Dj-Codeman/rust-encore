use hex;
use ring::pbkdf2;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    str,
};

use crate::{
    config::{
        PRE_DEFINED_USERKEY,
        PUBLIC_MAP_DIRECTORY, SYSTEM_KEY_LOCATION, USER_KEY_LOCATION, USE_PRE_DEFINED_USERKEY,
    },
    encrypt::{create_hash, create_secure_chunk, decrypt, encrypt},
    system::{_dump, append_log, halt, notice, output, unexist, warn, VERSION},
};

// pbkdf Generator specs
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITTING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// ! ALL KEYS FOLLOW THIS STRUCT
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIndex {
    pub hash: String,
    pub parent: String, // Default master or userkey
    pub location: String,
    pub version: String,
    pub key: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkMap {
    pub location: String,
    pub version: String,
    pub chunk_num: u32,
    pub chunk_hsh: String,
    pub chunk_beg: u32,
    pub chunk_end: u32,
}

// ! KEY GENERATION SECTION
pub fn generate_user_key() -> bool {
    // todo add a readable way to allow users to have to input a master password
    // ! this is a key and a integrity check. the key is not stored but it is tested against a encrypted value

    let salt: String = fetch_key_data(String::from("systemkey")); // ! DEPRICATING USE FROM ARRAY
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut password_key = [0; 16]; // Setting the key size

    if USE_PRE_DEFINED_USERKEY {
        pbkdf2::derive(
            PBKDF2_ALG,
            iteration,
            salt.as_bytes(),
            PRE_DEFINED_USERKEY.as_bytes(),
            &mut password_key,
        );
    } else {
        notice("Please choose writing password");
        let password = read_password().unwrap();
        pbkdf2::derive(
            PBKDF2_ALG,
            iteration,
            salt.as_bytes(),
            &password.as_bytes(),
            &mut password_key,
        );
    }

    let userkey = hex::encode(&password_key);
    // * creating the integrity file

    let secret: String = "The hotdog man isn't real !?".to_string();
    let cipher_integrity: String = encrypt(secret, userkey, 1024);
    // ! ^ this will be static since key sizes are really small

    unexist(&USER_KEY_LOCATION);

    // creating the master.json file
    let mut userkey_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&USER_KEY_LOCATION)
        .expect("File could not written to");

    if let Err(e) = write!(userkey_file, "{}", cipher_integrity) {
        let mut msg: String = String::new();
        msg.push_str("Error couldn't write user key to the path specified:: '");
        msg.push_str(&String::from(e.to_string()));
        msg.push_str("'");
        append_log(&msg);
        halt(&msg);
        return false;
    }

    let checksum_string = create_hash(&cipher_integrity);

    // populated all the created data
    let userkey_json_data: KeyIndex = KeyIndex {
        hash: String::from(checksum_string),
        parent: String::from("SELF"),
        version: String::from(VERSION),
        location: String::from(USER_KEY_LOCATION),
        key: 0,
    };

    // formatting the json data
    let pretty_userkey_json = serde_json::to_string_pretty(&userkey_json_data).unwrap();

    // creating the json path
    let mut userkey_json_path: String = String::new();
    userkey_json_path.push_str(PUBLIC_MAP_DIRECTORY);
    userkey_json_path.push_str("/userkey.json");

    // Deleting and recreating the json file
    unexist(&userkey_json_path);

    // writting to the master.json file
    let mut userkey_json_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(userkey_json_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(userkey_json_file, "{}", pretty_userkey_json) {
        halt("Could not write json data to file");
    }

    notice("User authentication created");
    return true;
}

pub fn generate_system_array() -> bool {
    append_log("Creating system array");

    // writing the system key to the file specified
    unexist(&SYSTEM_KEY_LOCATION);

    // Creating the key file
    // ! Creating Header
    // ? ie <--RECS System Array Version RX.X.X-->\n
    // ? Rust Encryption Core System RECS
    // ? HEADER CHARSIZE 39
    let mut system_array_header: String = String::new();
    system_array_header.push_str("<--REcS System Array Version ");
    system_array_header.push_str(VERSION);
    system_array_header.push_str("-->\n"); //40

    // ! Creating Body
    let system_array_chunk: String = create_secure_chunk(); //81,000
    // ? Total possible keys 5060

    // ! Creating Footer
    let mut system_array_footer: String = String::new();
    system_array_footer.push_str("\n</--REcS System Array-->"); //81,025

    // ! Assembeling array
    let mut system_array: String = String::new();
    system_array.push_str(&system_array_header);
    system_array.push_str(&system_array_chunk);
    system_array.push_str(&system_array_footer);

    // opening the file to write data to it
    let mut system_array_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(SYSTEM_KEY_LOCATION)
        .expect("File could not be opened");

    // writing the data and checking for errors
    if let Err(_e) = write!(system_array_file, "{}", system_array) {
        warn("Could not write the system_array to the path specified");
        return false;
    }

    // !-------------- reading and phrasing the chunk array

    // ? Defining initial chunks parameters
    let mut chunk_number: u32 = 0;

    // ? Defining the the usable part of the file for key data
    const BEG_CHAR: u32 = 40;
    const END_CHAR: u32 = 80984; //80,999
    const CHUNK_SIZE: usize = 16; //5060

    // ? Defing read heads and initial reading ranges
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;
    let mut buffer: Vec<u8> = vec![0; CHUNK_SIZE];
    let mut chunk: String = String::new();
    let mut file = File::open(SYSTEM_KEY_LOCATION).unwrap();

    // ! idiot profing
    let range_len = range_end - range_start;

    if range_len < CHUNK_SIZE as u32 {
        halt("Invalid secret chunk legnth");
    }

    // reading chunks and crating hashes
    loop {
        file.seek(SeekFrom::Start(range_start as u64))
            .expect("Failed to set seak head");

        // Break loop if we try to read outside of the usable chunk data
        if range_start > END_CHAR {
            break;
        }

        match file.read_exact(&mut buffer) {
            Ok(_) => {
                // ! reading buffer and hasing

                for data in buffer.iter() {
                    chunk += &format!("{:02X}", data);
                }

                let chunk_hash: &str = &create_hash(&chunk);

                let chunk_map: ChunkMap = ChunkMap {
                    location: SYSTEM_KEY_LOCATION.to_string(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };
                    
                // ! Making the map path
                let mut chunk_map_path: String = String::new();
                chunk_map_path.push_str(PUBLIC_MAP_DIRECTORY);
                chunk_map_path.push_str("/chunk_");
                chunk_map_path.push_str(&String::from(chunk_number.to_string()));
                chunk_map_path.push_str(".map");
                unexist(&chunk_map_path);

                let pretty_chunk_map = serde_json::to_string_pretty(&chunk_map).unwrap();

                // ? Writing the maps
                let mut chunk_map_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .append(true)
                .open(chunk_map_path)
                .expect("File could not written to");

                if let Err(_e) = write!(chunk_map_file, "{}", pretty_chunk_map) {
                    warn("Could not write json data to file");
                    return false;
                }
                // todo remove after validating
                notice(&chunk);
                warn(&chunk_hash);                
            }
            Err(_) => break,
        }
        
        // ? restting the indexs
        chunk_number += 1;
        chunk = "".to_string();
        range_start = range_end;
        range_end += CHUNK_SIZE as u32;
    }

    append_log("Created system array !");
    return true;
}

pub fn auth_user_key() -> String {
    // ! patched to just used fixed key
    append_log("user key authentication request started");

    // Gathering the data for the password
    // output("BLUE", "Please input password :");
    std::io::stdout().flush().unwrap();
    // let password_0 = read_password().unwrap(); //* THIS Diffrenciates between config password reading and user input */
    let password_0 = PRE_DEFINED_USERKEY;

    // ? turning password_0 into the pbkey
    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut password_key = [0; 16]; // defining the key size

    pbkdf2::derive(
        PBKDF2_ALG,
        iteration,
        salt.as_bytes(),
        password_0.as_bytes(),
        &mut password_key,
    );

    let userkey = hex::encode(&password_key);
    let secret: String = "The hotdog man isn't real !?".to_string();

    let verification_ciphertext: String = fetch_key_data("userkey".to_string());

    let verification_result: String = decrypt(verification_ciphertext, userkey.clone());

    if verification_result == secret {
        return userkey;
    } else {
        append_log("Authentication request failed");
        halt("Auth error");
        return "".to_string(); // ! i want to do unconvetional things here
    }
}

// public for encrypt.rs



// todo change these security goals for multi system things
// ! DEPRICATING FOR ARRAY THINGS 
pub fn fetch_key_data(key: String) -> String {
    let schrodingers_path: String = fetch_key_path(key);

    // opening the file to write data to it
    let mut numbered_key_map = File::open(schrodingers_path).expect("File could not be opened");

    let mut numbered_key_map_string: String = String::new();

    numbered_key_map
        .read_to_string(&mut numbered_key_map_string)
        .expect("Unable to read the file");

    let numbered_key_map_data: KeyIndex = serde_json::from_str(&numbered_key_map_string).unwrap();

    // verifing key version
    if numbered_key_map_data.version != VERSION {
        append_log("KEY FETCH ERROR: VERSION MISMATCH SAVE DATA AND REINITIALIZE OR debug '--carry-over-key X'");

        output(
            "RED",
            "Mismatched key version. The version of encore used to write this key",
        );
        output("RED", "is not the same one reading it. \n");
        output(
            "RED",
            "To solve this export your secrets and re initialize encore. \n",
        );
        halt("If you know what your doing you can use the debug '--carry-over-key X option' THIS MIGHT BREAK THINGS");
    };

    // Reading the key data
    let mut location = File::open(numbered_key_map_data.location)
        .expect("I CAN'T OPEN THE FUCKING KEY WHAT DID YOU DO !>!>!>!");
    let mut key_data: String = String::new();

    location
        .read_to_string(&mut key_data)
        .expect("Unable to read the file");

    // Creating new hash to check key integrity
    let checksum_string: String = create_hash(&key_data);

    // Verifying the check sum of the key data
    if numbered_key_map_data.hash != checksum_string {
        let mut log: String = String::new();
        log.push_str("KEY NUMBER ");
        log.push_str(&String::from(numbered_key_map_data.key.to_string()));
        log.push_str(" HAS FAILED HASH INTEGRITY. ");
        log.push_str(" IF THIS IS INTENTIONAL USE THE --debug command to re hash the key.\n");
        log.push_str(" ANY DATA ENCRYPTED WITH THE KEY IS AT RISK OF BEING ILLEGIBLE");
        log.push_str(" I'D EXPORT ALL OF MY DATA TO ASSES ANY LOSES AND RE IMPORT");
        append_log(&log);

        halt("INVALID KEY HASH POTINTIAL TAMPERING DETECTED");
    };

    return key_data;
}


pub fn create_writing_key(key: String) -> String {
    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(&auth_user_key());

    let prekey = create_hash(&prekey_str);

    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "5260".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut final_key = [0; 16]; // this hopefully sets the byte size

    pbkdf2::derive(
        PBKDF2_WRITTING_ALG,
        iteration,
        salt.as_bytes(),
        prekey.as_bytes(),
        &mut final_key,
    );

    return hex::encode(final_key);
}
