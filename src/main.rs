mod functions;
#[path = "system/system.rs"] mod system;
#[path = "system/encrypt.rs"] mod encrypt;

use crate::{
    system::{halt, notice, warn, pass, min_arguments, fetch_arguments, HELP}, 
    functions::{append_log, show_help, version, initialize, create_writing_key, write, read, destroy}, 
    encrypt::{encrypt, decrypt}
};


fn main() {
    // Creating a basic input phraser 
    let arguments_array: Vec<_> = fetch_arguments();
    if min_arguments(1){

        let arg_1: &str = &arguments_array[1];
        // proceed to the cases
        match arg_1 {
            "--write" => {
                // the system:: is what allows you to use not inclusive functions from diffent module"
                if min_arguments(4) {
                    let filename = String::from(&arguments_array[2]);
                    let secret_owner = String::from(&arguments_array[3]);
                    let secret_name = String::from(&arguments_array[4]);

                    if write(filename, secret_owner, secret_name) {
                        pass("DONE");
                    } else {
                        halt("WRITTING FAILED");
                    }

                } else {
                    warn("Create write help");
                }
            }
            "--read" => { 
                if min_arguments(3) {
                    let secret_owner = String::from(&arguments_array[2]);
                    let secret_name = String::from(&arguments_array[3]);

                    if read(secret_owner, secret_name) {
                        pass("DONE");
                    } else {
                        halt("Reading FAILED");
                    }

                } else {
                    warn("Create read help help");
                }
            }
            "--debug" => {
                // let writing_key = create_writing_key("KLw6NY7i07gM8CxUYE06ywDI8baCG6JR".to_string());
                // notice(&writing_key);

                notice(&encrypt("This is data".to_string(), "KLw6NY7i07gM8CxUYE06ywDI8baCG6JR".to_string()));
                pass(&decrypt("cbf0cc5c716d86119b0aac18285f9526j5szHkcYQ0GQVZJR703cb86625c7362f23ee57f2952994d7c8988a1904965b7b3086edd61a75b6ce".to_string(), "KLw6NY7i07gM8CxUYE06ywDI8baCG6JR".to_string()));

                warn("making a  randon writing key");
                warn(&create_writing_key("22".to_string()));
                
                append_log(" DEBUG DUMP");
                notice("End debug");
            }
            "--forget" => {
                if min_arguments(3) {
                    let secret_owner = String::from(&arguments_array[2]);
                    let secret_name = String::from(&arguments_array[3]);
                    
                    if !destroy(secret_owner, secret_name) { halt("An error occoured while forgetting secret"); };
                } else {
                    halt("Need two arguments 1 given");
                }
            }
            "--help" => {
                show_help();
            }
            "--version" => {
                version();
            }
            "--initialize" => {
                initialize();
            }
            "--sanity" => {
                halt("Not implementd");
            }
            "--system-test" => {
                warn("system tests")
            }
            _ => {
                notice(HELP);
            }
        }
        
    } else {
        notice(HELP);
    }

}