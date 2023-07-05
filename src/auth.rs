use hex;
use serde::{Serialize, Deserialize};
use std::{io::{Write, prelude::* }, fs::{OpenOptions, File }, str};
use rpassword::read_password;
use ring::pbkdf2;


use crate::{
    system::{output, halt, warn, notice, VERSION, append_log, unexist}, 
    config::{KEY_GEN_UPPER_LIMIT, KEY_GEN_LOWER_LIMIT, PRE_DEFINED_USERKEY, PUBLIC_MAP_DIRECTORY, SYSTEM_KEY_LOCATION,
        COMMON_KEY_DIRECTORY, USER_KEY_LOCATION, USE_PRE_DEFINED_USERKEY},
    encrypt::{encrypt, decrypt, create_key, create_hash},
};


// pbkdf Generator specs
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITTING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// ! ALL KEYS FOLLOW THIS STRUCT
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIndex {
    pub hash:       String,
    pub parent:     String, // Default master or userkey
    pub location:   String,
    pub version:    String,
    pub key:        u32,
}

// ! KEY GENERATION SECTION 
pub fn generate_user_key() -> bool {
    // todo add a readable way to allow users to have to input a master password
    // ! this is a key and a integrity check. the key is not stored but it is tested against a encrypted value 

    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut password_key = [0; 16]; // Setting the key size

    if USE_PRE_DEFINED_USERKEY {
        pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
        PRE_DEFINED_USERKEY.as_bytes(), &mut password_key);
    } else {
        notice("Please choose writing password");
        let password = read_password().unwrap();
        pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
        &password.as_bytes(), &mut password_key);
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
        return false
    }
        
    let checksum_string = create_hash(cipher_integrity);

    // populated all the created data
    let userkey_json_data: KeyIndex = KeyIndex {
        hash:     String::from(checksum_string),
        parent:   String::from("systemkey"),
        version:  String::from(VERSION),
        location: String::from(USER_KEY_LOCATION),
        key:      KEY_GEN_UPPER_LIMIT+1,
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
    return true 
}

pub fn generate_system_key() -> bool {

    append_log("Creating system key");

    // creating the canonical path to the map
    let mut systemkey_json_directory: String = String::new();
    systemkey_json_directory.push_str(PUBLIC_MAP_DIRECTORY);
    systemkey_json_directory.push_str("/master.json");

    // generating the key data
    let system_key: String = create_key();

    // writing the system key to the file specified
    unexist(&SYSTEM_KEY_LOCATION);

    // opening the file to write data to it
    let mut systemkey_location = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(SYSTEM_KEY_LOCATION)
    .expect("File could not be opened");

    // writing the data and checking for errors
    if let Err(_e) = write!(systemkey_location, "{}", system_key) {
        warn("Could not write the SYSTEMKEY to the path specified");
        return false;
    }

    // generating the hash of the written key file
    let checksum_string = create_hash(system_key.clone());

    // populated all the created data
    let systemkey_json_data: KeyIndex = KeyIndex {
        hash:     String::from(checksum_string),
        parent:   String::from("SELF"),
        version:  String::from(VERSION),
        location: String::from(SYSTEM_KEY_LOCATION),
        key:      0,
    };

    // formatting the json data
    let pretty_systemkey_json = serde_json::to_string_pretty(&systemkey_json_data).unwrap();

    // Deleting and recreating the json file 
    unexist(&systemkey_json_directory);

    // writting to the master.json file
    let mut systemkey_json_file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(systemkey_json_directory)
    .expect("File could not written to");

    if let Err(_e) = writeln!(systemkey_json_file, "{}", pretty_systemkey_json) {
        warn("Could not write json data to file");
        return false;
    }
    
    append_log("Created system key !");
    return true;
}

pub fn generate_common_keys() -> bool {
    // Creating the numbered key 
    for k in KEY_GEN_LOWER_LIMIT..=KEY_GEN_UPPER_LIMIT {

        // creating the canonical path to the map
        let mut numbered_json_directory: String = String::new();
        numbered_json_directory.push_str(PUBLIC_MAP_DIRECTORY);
        numbered_json_directory.push_str("/");
        numbered_json_directory.push_str(&String::from(k.to_string()));
        numbered_json_directory.push_str(".json");

        // generating the key data
        let number_key: String = create_key();

        // creating key dir
        let mut numbered_key_directory: String = String::new();
        numbered_key_directory.push_str(COMMON_KEY_DIRECTORY);
        numbered_key_directory.push_str("/");
        numbered_key_directory.push_str(&String::from(k.to_string()));
        numbered_key_directory.push_str(".dk");

        unexist(&numbered_key_directory);

        // opening the file to write data to it
        let mut numbered_key_location = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&numbered_key_directory)
        .expect("File could not be opened");

        // writing the data and checking for errors
        if let Err(e) = write!(numbered_key_location, "{}", number_key) {
            let mut msg: String = String::new();
            msg.push_str("Error writing common keys to the path specified:: '");
            msg.push_str(&String::from(e.to_string()));
            msg.push_str("'");
            warn(&msg);
            return false;
        }

        let checksum_string = create_hash(number_key.clone());

        // populated all the created data
        let numbered_json_data: KeyIndex = KeyIndex {
            hash:     String::from(checksum_string),
            parent:   String::from("systemkey"),
            version:  String::from(VERSION),
            location: String::from(numbered_key_directory),
            key:      k,
        };

        // formatting the json data
        let pretty_numbered_json = serde_json::to_string_pretty(&numbered_json_data).unwrap();

        // Deleting and recreating the json file 
        unexist(&numbered_json_directory);

        // writting to the master.json file
        let mut numbered_json_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(numbered_json_directory)
        .expect("File could not written to");

        if let Err(e) = writeln!(numbered_json_file, "{}", pretty_numbered_json) {
            let mut msg: String = String::new();
            msg.push_str("Error writing common json to the path specified:: '");
            msg.push_str(&String::from(e.to_string()));
            msg.push_str("'");
            output("RED",&msg);
            return false;
        }

        let mut msg: String = String::new();
        msg.push_str(&String::from(k.to_string()));
        msg.push_str("x key pair created");
        append_log(&msg);

    } // generating numbered pairs
    append_log("common keys created !");
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

    pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
        password_0.as_bytes(), &mut password_key);

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
pub fn fetch_key_data(key: String) -> String {
    let schrodingers_path: String = fetch_key_path(key);

    // opening the file to write data to it
    let mut numbered_key_map = File::open(schrodingers_path)
    .expect("File could not be opened");

    let mut numbered_key_map_string: String = String::new();

    numbered_key_map.read_to_string(&mut numbered_key_map_string).expect("Unable to read the file");
    
    let numbered_key_map_data: KeyIndex = serde_json::from_str(&numbered_key_map_string).unwrap();

    // verifing key version
    if numbered_key_map_data.version != VERSION {
        append_log("KEY FETCH ERROR: VERSION MISMATCH SAVE DATA AND REINITIALIZE OR debug '--carry-over-key X'");

        output("RED", "Mismatched key version. The version of encore used to write this key");
        output("RED", "is not the same one reading it. \n");
        output("RED", "To solve this export your secrets and re initialize encore. \n");
        halt("If you know what your doing you can use the debug '--carry-over-key X option' THIS MIGHT BREAK THINGS");
    
    };

    // Reading the key data
    let mut location = File::open(numbered_key_map_data.location)
    .expect("I CAN'T OPEN THE FUCKING KEY WHAT DID YOU DO !>!>!>!");
    let mut key_data: String = String::new();
    
    location.read_to_string(&mut key_data).expect("Unable to read the file");

    // Creating new hash to check key integrity
    let checksum_string: String = create_hash(key_data.clone());

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

// public for encrypt.rs
pub fn fetch_key_path(key: String) -> String {
    if key == "systemkey".to_string() {
        let mut path:String = String::new();
        path.push_str(PUBLIC_MAP_DIRECTORY);
        path.push_str("/master.json");
        return path;

    } else if key == "userkey".to_string() {
        let mut path:String = String::new();
        path.push_str(PUBLIC_MAP_DIRECTORY);
        path.push_str("/userkey.json");
        return path;

    } else {
        let mut path:String = String::new();
        path.push_str(PUBLIC_MAP_DIRECTORY);
        path.push_str("/");
        path.push_str(&String::from(key));
        path.push_str(".json");
        return path;
    }
}

pub fn create_writing_key(key: String) -> String {

    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(&auth_user_key());
    
    let prekey = create_hash(prekey_str);

    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "5260".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut final_key = [0; 16]; // this hopefully sets the byte size

    pbkdf2::derive(PBKDF2_WRITTING_ALG, iteration, salt.as_bytes(),
        prekey.as_bytes(), &mut final_key);

    return hex::encode(final_key);
}