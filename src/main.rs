mod functions;
#[path = "system/system.rs"] mod system;
#[path = "system/encrypt.rs"] mod encrypt;
#[path = "system/encrypt_functions.rs"] mod encrypt_functions;

use crate::{
    system::{halt, notice, warn, pass, min_arguments, fetch_arguments, HELP, append_log}, 
    functions::{show_help, version, initialize}, 
    encrypt_functions::{write, read, forget}
};

// use std::env;

fn main() {
    // ? SHOW ME THE STACK !
    // env::set_var("RUST_BACKTRACE", "1");
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
                let arg_2: &str = &arguments_array[2];
                // proceed to the cases
                match arg_2 {

                    "--write" => {
                        let filename = String::from(&arguments_array[3]);
                        let secret_owner = String::from(&arguments_array[4]);
                        let secret_name = String::from(&arguments_array[5]);
                        
                        if write(filename, secret_owner, secret_name) {
                            pass("\n Done ");
                        }
                    }

                    "--read" => {
                        let secret_owner = String::from(&arguments_array[3]);
                        let secret_name = String::from(&arguments_array[4]);

                        read(secret_owner, secret_name); 
                    }

                    _ => {
                        notice(HELP);
                    }
                }
                append_log(" DEBUG DUMP");
                notice("End debug");
            }
            "--forget" => {
                if min_arguments(3) {
                    let secret_owner = String::from(&arguments_array[2]);
                    let secret_name = String::from(&arguments_array[3]);
                    
                    if !forget(secret_owner, secret_name) { halt("An error occoured while forgetting secret"); };
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