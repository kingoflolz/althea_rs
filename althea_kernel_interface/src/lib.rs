#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

extern crate eui48;
extern crate itertools;
extern crate regex;

use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::path::Path;

use std::str;

use eui48::MacAddress;

mod counter;
mod create_wg_key;
mod delete_tunnel;
mod exit_client_counter;
mod exit_client_tunnel;
mod exit_server_counter;
mod exit_server_tunnel;
mod get_neighbors;
mod get_wg_pubkey;
mod interface_tools;
mod link_local_tools;
mod manipulate_uci;
mod open_tunnel;
mod openwrt_ubus;
mod setup_wg_if;

pub use counter::FilterTarget;
pub use exit_server_counter::ExitFilterTarget;
pub use exit_server_tunnel::ExitClient;

use failure::Error;

#[derive(Debug, Fail)]
pub enum KernelInterfaceError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|program, args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(LinuxCommandRunner {});
}

pub trait CommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error>;
    fn set_mock(&self, mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>);
}

pub struct LinuxCommandRunner;

impl CommandRunner for LinuxCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let start = Instant::now();
        let output = Command::new(program).args(args).output()?;

        trace!("Command {:?} {:?} returned: {:?}", program, args, output);
        if !output.status.success() {
            info!(
                "Command {:?} {:?} returned: an error {:?}",
                program, args, output
            );
        }
        trace!(
            "command completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_nanos() / 1000000
        );
        return Ok(output);
    }

    fn set_mock(&self, mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        unimplemented!()
    }
}

pub struct TestCommandRunner {
    pub run_command: Arc<Mutex<Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>>>,
}

impl CommandRunner for TestCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let mut args_owned = Vec::new();
        for a in args {
            args_owned.push(a.to_string())
        }

        (&mut *self.run_command.lock().unwrap())(program.to_string(), args_owned)
    }

    fn set_mock(&self, mock: Box<FnMut(String, Vec<String>) -> Result<Output, Error> + Send>) {
        *self.run_command.lock().unwrap() = mock
    }
}

pub trait KernelInterface: CommandRunner + Sync{}

impl KernelInterface for LinuxCommandRunner{}
impl KernelInterface for TestCommandRunner{}