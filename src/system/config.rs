
	// LOCATIONS
	//  Data this is where the finished and encrypted files live
	//  When keys are regenerated this folder will be emptyied
	//  default /var/encore/data

pub const DATA_DIRECTORY: &str = "/var/encore/secrets";


	//  JSON This is where plan text maps will live
	//  these are generated along side the keys
	//  default /var/encore/indexs

pub const PUBLIC_MAP_DIRECTORY: &str = "/var/encore/key-maps";

	//  This is where the encrypted jsons for written file
	//  will live. The json debug tool should be used to decrypt
	//  and modify these files

pub const SECRET_MAP_DIRECTORY: &str = "/var/encore/secret-maps";

	//  KEY These are the random encryption keys
	//  128 bit strings for use with the encrypt script
	//  https://www.fastsitephp.com/fr/documents/file-encryption-bash
	//  default /opt/encore/keys

pub const COMMON_KEY_DIRECTORY: &str = "/var/encore/keys";

	//  SYSTEM KEY JSON file that contain location and key information
	//  are encrypted using this key
	//  if this key is missing on script call all file in:
	//  $datadir will be illegible
	//  IF THIS KEY IS DELETED ALL DATA IS CONSIDERED LOST
	//  default /opt/encore/keys/systemkey.dk


pub const SYSTEM_KEY_LOCATION: &str = "/var/systemkey.dk";

	//	The user key is derived from the users specific password
	//	This is the key used to encrypt the files them selfs while
	//	the maps and indexs will still use the system key
	//  if this key is missing on script call all file in:
	//  $datadir will be illegible
	//  IF THIS KEY IS DELETED ALL DATA IS CONSIDERED LOST

pub const USER_KEY_LOCATION: &str = "/var/userkey.dk";

	// log dir

// pub const LOG_FILE_LOCATION: &str = "/var/log/encore/general";
pub const LOG_FILE_LOCATION: &str = "/var/encore/general";

	//  key_max the limit of keys to generate
	//  default=50000

pub const KEY_GEN_UPPER_LIMIT: u32 = 5000;

	//  Works like a key min value
	//  by key_cur and key_max the range from which keys are picked
	//  can be changed

pub const KEY_GEN_LOWER_LIMIT: u32 = 0;

	// currently for debuging 
	// the stream buffer will be dynamically assigned at runtime
	// if this space is not available on run time exit with "No free resources"
	// dynamiclly allocated write should have this functionallity built in too 
	// 1Mb 

pub const STREAMING_BUFFER_SIZE: f64 = 102400.00;

	//  soft moving
	//  set 1 to use cp instead of mv when gatheing files to encrypt
	//  default = false

pub const SOFT_MOVE_FILES: bool = false;

	//  re-place file
	//  the original path of files are stored when encrypted
	//  if set files will be re placed back in there original
	//  directory
	//  default= true


// ! safe to dep ?
pub const _REPLACE_FILE_ON_DEL: bool = true;

	//  save on destroy
	//  if you want the destroy function to recover the file before deleting
	//  the encrypted copy set this true
	//  default = true


pub const LEAVE_IN_PEACE: bool = false;

	// PRE DEFINED SECRET 
	// if you use encore when no password can be input the userkey prompt can 
	// be skipped by defining a a secret value here 
	// THIS IS LESS SECURE BECAUSE THE KEY IS TECHNICALLY STORED ON THE MACHINE

// TODO use this somewhere
pub const _USE_PRE_DEFINED_USERKEY: bool = true;
pub const PRE_DEFINED_USERKEY: &str = "Secret1!";
