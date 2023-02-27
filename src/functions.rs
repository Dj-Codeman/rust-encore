#[path = "system/system.rs"] mod system;
#[path = "system/config.rs"] mod config;
#[path = "system/encrypt.rs"] mod encrypt;
// includes
use chrono::{Datelike, DateTime, Timelike, Local};
use base64::{encode};
use hex;
use serde::{Serialize, Deserialize};
use std::{io::{Write, prelude::*}, fs::{OpenOptions, File, canonicalize, remove_dir_all, create_dir_all, read_to_string}, path::Path, str};
use rpassword::read_password;
use ring::pbkdf2;
use rand::distributions::{Distribution, Uniform};

use self::{
    system::{output, halt, warn, notice, pass, VERSION, HELP, truncate}, 
    config::{KEY_GEN_UPPER_LIMIT, KEY_GEN_LOWER_LIMIT, PRE_DEFINED_USERKEY, USE_PRE_DEFINED_USERKEY, PUBLIC_MAP_DIRECTORY, SYSTEM_KEY_LOCATION,
        COMMON_KEY_DIRECTORY, USER_KEY_LOCATION, SECRET_MAP_DIRECTORY, DATA_DIRECTORY, REPLACE_FILE_ON_DEL, LEAVE_IN_PEACE, SOFT_MOVE_FILES},
    encrypt::{encrypt, decrypt, create_key, create_hash}
};

// pbkdf parameters
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITTING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;


// Version output 
pub fn version() {
    let mut msg: String = String::new();
    msg.push_str("Version: ");
    msg.push_str(system::VERSION);
    system::pass(&msg);
}

#[derive(Serialize, Deserialize, Debug)]
struct SecretDataIndex {
    version:        String,
    name:           String,
    owner:          String,
    key:            u32,
    unique_id:      String,
    file_path:      String,
    secret_path:    String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyIndex {
    hash:       String,
    parent:     String, // Default master or userkey
    location:   String,
    version:    String,
    key:        u32,
}

fn timestamp() -> String {
    // Getting the data 
    let mut timestamp: String = String::new();
    let current_time: DateTime<Local> = Local::now();

    let day: u32 = current_time.day();
    let month: u32 = current_time.month();
    let year: i32 = current_time.year();
    let hour: u32 = current_time.hour();
    let minute: u32 = current_time.minute();
    let second: u32 = current_time.second();

    // adding foward 0 padding to dates
    let year_string: String = year.to_string();

    fn padding_date(number: u32) -> String {
        if number < 10 {
            let mut local_date_string = String::new();
            local_date_string.push_str("0");
            local_date_string.push_str(&number.to_string());
            return local_date_string;

        } else {
            let local_date_string: String = String::from(&number.to_string());
            return local_date_string;
        }

    }

    timestamp.push_str(&year_string);
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(month));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(day));
    timestamp.push_str("_");
    timestamp.push_str(&padding_date(hour));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(minute));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(second));

    return timestamp;
}

fn start_log() {
    let mut log_msg: String = String::new();
    log_msg.push_str(" LOG START");
    log_msg.push_str(" @ ");
    log_msg.push_str(&timestamp());
    log_msg.push_str("\n");
    // write to log function

    // if al old log exists delete it
    if std::path::Path::new(config::LOG_FILE_LOCATION).exists() {
        std::fs::remove_file(config::LOG_FILE_LOCATION).unwrap();
      }
      
    // create new log file
    let mut log_file = OpenOptions::new().create_new(true).write(true).append(true).open(config::LOG_FILE_LOCATION).expect("File could not be opened");

    if let Err(_e) = writeln!(log_file, "{}", log_msg) {
        halt("Could not create or write to new log file");
    }

    let msg: String = String::from("Log Created! \n");
    system::output("GREEN", &msg);
}

pub fn append_log(data: &str) {
    // Makign data
    let mut log_msg: String = String::new();
    log_msg.push_str(data);
    log_msg.push_str(" @ ");
    log_msg.push_str(&timestamp());
    log_msg.push_str("\n");

    // Opening the file
    let mut log_file = OpenOptions::new().write(true).append(true).open(config::LOG_FILE_LOCATION).expect("File could not be opened");

    // Hendeling errs
    if let Err(_e) = writeln!(log_file, "{}", log_msg) {
        warn("Couldn't open already existing log file");
    }
}

pub fn generate_userkey() {

    if USE_PRE_DEFINED_USERKEY == false {
        output("GREEN", "Setting up authentication \n");
        append_log("Setting up userkey authentication");

        // Gathering the data for the password
        output("BLUE", "Please chose a password :");
        std::io::stdout().flush().unwrap();
        let password_0 = read_password().unwrap();

        // gathering the second passwords
        output("GREEN", "Please retype password :");
        std::io::stdout().flush().unwrap();
        let password_1 = read_password().unwrap();

        if !check_match(&password_0, &password_1) {
            warn("Passwords do not match !!!!");
        } else {
            if !write_userkey_data(password_0) {
                halt("Unable to write userkey");
            }
        }

    } else {
        output("GREEN", "Setting up authentication \n");
        append_log("Setting up userkey authentication");
        if  !write_userkey_data(PRE_DEFINED_USERKEY.to_string()) {
            halt("Unable to write userkey");
        }
    }

    // the variables for matching couldn't be passed to the if 
    // so we made a function for it

    fn check_match(p0: &str, p1: &str ) -> bool {
        if p0 == p1 {
    
            // checking safty of the password
            let password: &str = p0;
            let password_legnth: usize = password.len(); 

            if password_legnth > 255 {
                warn("Password is too big ");
                return false

            } else if password_legnth <= 1 {
                warn("Password is too small");
                return false

            } else {
                return true
            }
    
        } else {
            return false
        }
    }
}

fn generate_systemkey() {
    output("GREEN", "Recreating key-map pairs \n");
    append_log("Started key and map pair generation");

    // creating the canonical path to the map
    let mut systemkey_json_directory: String = String::new();
    systemkey_json_directory.push_str(PUBLIC_MAP_DIRECTORY);
    systemkey_json_directory.push_str("/master.json");

    // generating the key data
    let system_key: String = create_key();

    // writing the system key to the file specified
    if std::path::Path::new(&SYSTEM_KEY_LOCATION).exists() { // deleting the original one
        std::fs::remove_file(&SYSTEM_KEY_LOCATION).unwrap();
    }

    // opening the file to write data to it
    let mut systemkey_location = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(SYSTEM_KEY_LOCATION)
    .expect("File could not be opened");

    // writing the data and checking for errors
    if let Err(_e) = write!(systemkey_location, "{}", system_key) {
        halt("Could not write the SYSTEMKEY to the path specified");
    }

    // WRITE TO KEY TO FILE THEN TAKE THE CHECKSUM
    // open key file
    let mut location = File::open(SYSTEM_KEY_LOCATION)
    .expect("I CAN'T OPEN THE FUCKING KEY WHAT DID YOU DO !>!>!>!");

    let mut systemkey_data: String = String::new();
    
    location.read_to_string(&mut systemkey_data).expect("Unable to read the file");

    // generating the hash of the written key file
    let checksum_string = create_hash(systemkey_data.clone());

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
    if std::path::Path::new(&systemkey_json_directory).exists() { // deleting the original one
        std::fs::remove_file(&systemkey_json_directory).unwrap();
    }

    // writting to the master.json file
    let mut systemkey_json_file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(systemkey_json_directory)
    .expect("File could not written to");

    if let Err(_e) = writeln!(systemkey_json_file, "{}", pretty_systemkey_json) {
        halt("Could not write json data to file");
    }
    
    notice("System key pair created");
    append_log("System key pair created");
}

fn generate_keys() {
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

        // writing the system key to the file specified
        // creating key dir
        let mut numbered_key_directory: String = String::new();
        numbered_key_directory.push_str(COMMON_KEY_DIRECTORY);
        numbered_key_directory.push_str("/");
        numbered_key_directory.push_str(&String::from(k.to_string()));
        numbered_key_directory.push_str(".dk");

        if std::path::Path::new(&numbered_key_directory).exists() { // deleting the original one
            std::fs::remove_file(&numbered_key_directory).unwrap();
        }

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
            halt(&msg);
            // eprintln!("Couldn't write to file: {}", e);
        }

        // open key file
        let mut location = File::open(numbered_key_directory.clone())
        .expect("I CAN'T OPEN THE FUCKING KEY WHAT DID YOU DO !>!>!>!");

        let mut key_data: String = String::new();

        location.read_to_string(&mut key_data).expect("Unable to read the file");

        // generating the hash of the written key file
        let checksum_string = create_hash(key_data.clone());

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
        if std::path::Path::new(&numbered_json_directory).exists() { // deleting the original one
            std::fs::remove_file(&numbered_json_directory).unwrap();
        }

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
            halt(&msg);
        }

        let mut msg: String = String::new();
        msg.push_str(&String::from(k.to_string()));
        msg.push_str("x key pair created");
        append_log(&msg);

    } // generating numbered pairs

    output("GREEN", "Keys created. \n");
}

fn write_userkey_data(password: String) -> bool {
                
    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut password_key = [0; 16]; // this hopefully sets the byte size

    pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
        password.as_bytes(), &mut password_key);

    let userkey = hex::encode(&password_key);
    let secret: String = "The hotdog man isn't real !?".to_string();

    let ciphertext: String = encrypt(secret, userkey);

    // write the cipher text to user key

    // Deleting and recreating the json file 
    if std::path::Path::new(&USER_KEY_LOCATION).exists() { // deleting the original one
        std::fs::remove_file(&USER_KEY_LOCATION).unwrap();
    }

    // writting to the master.json file
    let mut userkey_file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(&USER_KEY_LOCATION)
    .expect("File could not written to");

    if let Err(e) = write!(userkey_file, "{}", ciphertext) {
        let mut msg: String = String::new();
        msg.push_str("Error couldn't write user key to the path specified:: '");
        msg.push_str(&String::from(e.to_string()));
        msg.push_str("'");
        append_log(&msg);
        halt(&msg);
        return false
    }
        
    // open key file
    let mut location = File::open(USER_KEY_LOCATION)
    .expect("I CAN'T OPEN THE FUCKING KEY WHAT DID YOU DO !>!>!>!");

    let mut userkey_data: String = String::new();
    
    location.read_to_string(&mut userkey_data).expect("Unable to read the file");

    // generating the hash of the written key file
    let checksum_string = create_hash(userkey_data.clone());

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
    if std::path::Path::new(&userkey_json_path).exists() { // deleting the original one
        std::fs::remove_file(&userkey_json_path).unwrap();
    }

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

fn verify_userkey_data() -> String {
    if USE_PRE_DEFINED_USERKEY == false {
        output("GREEN", "Verifying userkey \n");
        append_log("Setting up userkey authentication");

        // Gathering the data for the password
        output("BLUE", "Please input password :");
        std::io::stdout().flush().unwrap();
        let password_0 = read_password().unwrap();

        // ? turning password_0 into the pbkey
        let salt: String = fetch_key_data(String::from("systemkey"));
        let num: u32 = "95180".parse().expect("Not a number!");
        let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
        let mut password_key = [0; 16]; // this hopefully sets the byte size
    
        pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
            password_0.as_bytes(), &mut password_key);
    
        let userkey = hex::encode(&password_key);
        let secret: String = "The hotdog man isn't real !?".to_string();

        let verification_ciphertext: String = fetch_key_data("userkey".to_string());

        let verification_result: String = decrypt(verification_ciphertext, userkey.clone());

        if verification_result == secret {
            return userkey;
        } else {
            halt ("Invalid password");
            return "".to_string();
        }

    } else {
        let salt: String = fetch_key_data(String::from("systemkey"));
        let num: u32 = "95180".parse().expect("Not a number!");
        let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
        let mut password_key = [0; 16]; // this hopefully sets the byte size

        pbkdf2::derive(PBKDF2_ALG, iteration, salt.as_bytes(),
        PRE_DEFINED_USERKEY.as_bytes(), &mut password_key);

        let userkey = hex::encode(&password_key);
        return userkey;

    }
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

// public for encrypt.rs
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

        warn("INVALID KEY HASH POTINTIAL TAMPERING DETECTED");
    };

    return key_data;
}

pub fn create_writing_key(key: String) -> String {

    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(&verify_userkey_data());
    
    let prekey = create_hash(prekey_str);

    let salt: String = fetch_key_data(String::from("systemkey"));
    let num: u32 = "5260".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(u32::from(num)).unwrap();
    let mut final_key = [0; 16]; // this hopefully sets the byte size

    pbkdf2::derive(PBKDF2_WRITTING_ALG, iteration, salt.as_bytes(),
        prekey.as_bytes(), &mut final_key);

    return hex::encode(final_key);
}

pub fn write(filename: String, secret_owner: String, secret_name: String) -> bool {
    // make something cool
    output("GREEN", "Writing secret \n");
    // creating the message to log
    let mut msg: String = String::new();
    msg.push_str("Attempting to encrypt '");
    msg.push_str(&filename);
    msg.push_str("'");
    append_log(&msg);

    // testing if the file exists
    let filename_existence: bool = Path::new(&filename).exists();

    if filename_existence {
        // creating the secret json file 
        let mut secret_map_path: String = String::new();
        secret_map_path.push_str(SECRET_MAP_DIRECTORY);
        secret_map_path.push_str("/");
        secret_map_path.push_str(&secret_owner);
        secret_map_path.push_str("-");
        secret_map_path.push_str(&secret_name);
        secret_map_path.push_str(".json");
        // testing if the secret json exists before starting encryption
        let secret_json_existence: bool = Path::new(&secret_map_path).exists();
        if secret_json_existence {
            warn("The owner, name combo exists");
            return false
        } else {
            // using the rand crate pick a num between our range
            let mut rng = rand::thread_rng();
            let range = Uniform::new(KEY_GEN_LOWER_LIMIT, KEY_GEN_UPPER_LIMIT);
            let key = range.sample(&mut rng);
            // creating the rest of the struct data
            let unique_id: String = truncate(&encode(create_hash(filename.clone())), 20).to_string();
            let canon_path = canonicalize(&filename).expect("path doesn't exist").display().to_string();
            // create the secret path
            let mut secret_path = String::new();
            secret_path.push_str(DATA_DIRECTORY);
            secret_path.push_str("/");
            secret_path.push_str(&unique_id);
            // Creating the struct
            let secret_data_map: SecretDataIndex = SecretDataIndex {
                version: String::from(VERSION),
                name: String::from(&secret_name),
                owner: String::from(&secret_owner),
                key: key,
                unique_id: unique_id,
                file_path: canon_path,
                secret_path: secret_path.clone(),
                
            };

            // formatting the json data
            let pretty_secret_data_map = serde_json::to_string_pretty(&secret_data_map).unwrap();
            let cipher_secret_data_map = encrypt(pretty_secret_data_map, fetch_key_data("systemkey".to_string()));
            // wait the write this data till the file has been encrypted

            // this reads the entire file into a buffer
            let file = File::open(filename);
            let mut buffer = Vec::new();
            file.expect("couldn't open the file").read_to_end(&mut buffer).expect("wait can you do this");

            // encrypting the file
            let plain_file = hex::encode(buffer);
            let secret_data = encrypt(plain_file, create_writing_key(key.to_string()));

            // create file or die
            let mut paths = vec![];
            paths.insert(0, secret_map_path.clone());
            paths.insert(1, secret_path.clone());

            for path in paths.iter() {
                if std::path::Path::new(&path).exists() {
                    append_log("Files exist with the the same unique ids this is most likely a collision consider changing file names and trying again");
                    halt("UNCLEAN ENV CHECK LOG");
                }
            }
            // writting to secret data
            let mut secret_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(secret_path)
            .expect("File could not written to");

            if let Err(_) = write!(secret_file, "{}", secret_data) {
                halt(&"Could't write the encrypted data");
            }

            // writting to secret data json file
            let mut secret_map_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(secret_map_path)
            .expect("File could not written to");

            if let Err(_) = write!(secret_map_file, "{}", cipher_secret_data_map) {
                halt(&"Could't write the encrypted data");
            }
        
            // after everything has been written we can delete the file 
            if !SOFT_MOVE_FILES {
                std::fs::remove_file(secret_data_map.file_path).unwrap();
            }
        }

        return true

    } else {
        notice(&filename);
        warn("File doesn't exist");
        return false
    }

    // why is this needed ???
    // ! Rewrite the if contitional because this should be inaccessible
    // return true
} 

pub fn read(secret_owner: String, secret_name: String) -> bool {
    // creating the secret json file 
    append_log("Decrypting request");
    let mut secret_map_path: String = String::new();
    secret_map_path.push_str(SECRET_MAP_DIRECTORY);
    secret_map_path.push_str("/");
    secret_map_path.push_str(&secret_owner);
    secret_map_path.push_str("-");
    secret_map_path.push_str(&secret_name);
    secret_map_path.push_str(".json");
    // testing if the secret json exists before starting encryption
    let secret_json_existence: bool = Path::new(&secret_map_path).exists();
    if secret_json_existence {
        let cipher_map_data = read_to_string(secret_map_path).expect("Couldn't read the json file");        
        let secret_map_data = decrypt(cipher_map_data, fetch_key_data("systemkey".to_string()));

        let secret_map: SecretDataIndex = serde_json::from_str(&secret_map_data).unwrap();

        // checking data version 
        if secret_map.version != VERSION {
            halt("DATA VERSION MISMATCHED. If you know what your doing use the debug commands");
        }
        
        // ensure the data is there
        if !std::path::Path::new(&secret_map.secret_path).exists() {
            halt("THE DATA FILE SPECIFIED DOES NOT EXIST");
        }

        // generating the secret key for the file
        let writting_key: String = create_writing_key(secret_map.key.to_string());

        // reading data to file 
        let cipher_file_data: String = read_to_string(secret_map.secret_path).expect("Couldn't read the cipher file");        
        // decrypting the data 
        let plain_hex_file_data: String = decrypt(cipher_file_data, writting_key);
        let plain_file_data = hex::decode(plain_hex_file_data).expect("Data couldn't be read");

        if REPLACE_FILE_ON_DEL {
            // TODO add a warning and a contition if the file exists
            let mut plain_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(secret_map.file_path)
            .expect("File could not written to");
            
            plain_file.write_all(&plain_file_data).expect("failed writing to the path given");
        } else {
            let mut path: String = String::new();
            path.push_str(&secret_map.unique_id);
            path.push_str(".dec");

            let mut plain_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(path)
            .expect("File could not written to");
            
            plain_file.write_all(&plain_file_data).expect("failed writing to the path given");
        }

        return true
    } else {
        warn("The secret map doen't exist");
        return false
    }
}

pub fn destroy(secret_owner: String, secret_name: String) -> bool {
    // creating the secret json file 
    append_log("Forgetting secret");
    let mut secret_map_path: String = String::new();
    secret_map_path.push_str(SECRET_MAP_DIRECTORY);
    secret_map_path.push_str("/");
    secret_map_path.push_str(&secret_owner);
    secret_map_path.push_str("-");
    secret_map_path.push_str(&secret_name);
    secret_map_path.push_str(".json");
    // testing if the secret json exists before starting encryption
    let secret_json_existence: bool = Path::new(&secret_map_path).exists();
    if secret_json_existence {
         let cipher_map_data = read_to_string(secret_map_path.clone()).expect("Couldn't read the json file");        
         let secret_map_data = decrypt(cipher_map_data, fetch_key_data("systemkey".to_string()));
         let secret_map: SecretDataIndex = serde_json::from_str(&secret_map_data).unwrap();
         // the config 
         if LEAVE_IN_PEACE {
             if read(secret_owner, secret_name) { warn("File read before deleting"); }
             
             // deleted secret data 
             if std::path::Path::new(&secret_map.secret_path).exists() {
                 std::fs::remove_file(&secret_map.secret_path).unwrap();
             }
             std::fs::remove_file(&secret_map_path).unwrap();
         } else {
             // deleted secret data 
             if std::path::Path::new(&secret_map.secret_path).exists() {
                 std::fs::remove_file(&secret_map.secret_path).unwrap();
             }
             std::fs::remove_file(&secret_map_path).unwrap();
         }
         return true
    } else {
        return false
    }
}
// TODO add some debugging tools
fn make_folders() {
    output("GREEN", "Making directories \n");
    create_dir_all("/var/encore").expect("making folders failed");

    let mut paths = vec![];
    paths.insert(0, DATA_DIRECTORY);
    paths.insert(1, PUBLIC_MAP_DIRECTORY);
    paths.insert(2, SECRET_MAP_DIRECTORY);
    paths.insert(3, COMMON_KEY_DIRECTORY);
    paths.insert(4, "/var/log/encore");

    for path in paths.iter() {
        if std::path::Path::new(&path).exists() {
            remove_dir_all(path).expect("couldn't delete folders");
            create_dir_all(path).expect("making folders failed");
        }
    }
}

pub fn show_help() {
    notice(HELP);
}

pub fn initialize() {
    make_folders();

    start_log();

    generate_systemkey();

    generate_userkey();

    generate_keys();

    pass("System initialized");
}