#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

use std::net::{IpAddr, SocketAddr};

extern crate settings;

extern crate ipgen;
extern crate rand;
use rand::{thread_rng, Rng};

use std::str;

use failure::Error;

extern crate reqwest;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use settings::ExitClientDetails;
use std::time::Duration;
use std::path::Path;
use althea_types::interop::ExitServerIdentity;
use regex::Regex;

extern crate althea_types;
extern crate regex;

#[derive(Debug, Fail)]
pub enum CluError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

fn linux_generate_wg_keys(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    let mut ki = KernelInterface {};
    let keys = ki.create_wg_keypair()?;
    let wg_public_key = &keys[0];
    let wg_private_key = &keys[1];

    //Mutates settings, intentional side effect
    config.write().unwrap().network.wg_private_key = wg_private_key.to_string();
    config.write().unwrap().network.wg_public_key = wg_public_key.to_string();

    Ok(())
}

fn openwrt_generate_and_set_wg_keys(
    config: Arc<RwLock<settings::RitaSettings>>,
) -> Result<(), Error> {
    let mut ki = KernelInterface {};
    let keys = ki.create_wg_keypair()?;
    let wg_public_key = &keys[0];
    let wg_private_key = &keys[1];

    let ret = ki.set_uci_var("network.wgExit.private_key", &wg_private_key);
    ret.expect("Failed to set UCI var! {:?}");
    let ret = ki.uci_commit();
    ret.expect("Failed to commit UCI changes!");

    //Mutates settings, intentional side effect
    config.write().unwrap().network.wg_private_key = wg_private_key.to_string();
    config.write().unwrap().network.wg_public_key = wg_public_key.to_string();

    Ok(())
}

fn linux_generate_mesh_ip(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    let seed: String = thread_rng().gen_ascii_chars().take(50).collect();
    let mesh_ip = ipgen::ip(&seed, "fd::/120").unwrap();

    trace!("generated new ip address {}", mesh_ip);

    // Mutates Settings intentional side effect
    config.write().unwrap().network.own_ip = mesh_ip;
    Ok(())
}

fn openwrt_generate_mesh_ip(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    let ki = KernelInterface {};
    let seed = rand::thread_rng().gen::<[u8; 10]>();
    let mesh_ip = ipgen::ip(std::str::from_utf8(&seed)?, "fd::/120").unwrap();

    // Mutates Settings intentional side effect
    config.write().unwrap().network.own_ip = mesh_ip;

    ki.uci_commit().unwrap();
    Ok(())
}

fn validate_wg_key(key: &str) -> bool {
    if key.len() != 44 || !key.ends_with("=") {
        false
    } else {
        true
    }
}

fn validate_mesh_ip(ip: &IpAddr) -> bool {
    if !ip.is_ipv6() || ip.is_unspecified() {
        false
    } else {
        true
    }
}

fn linux_setup_exit_tunnel(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    let ki = KernelInterface {};

    let details = config
        .read()
        .unwrap()
        .clone()
        .exit_client
        .unwrap()
        .details
        .unwrap();

    ki.setup_wg_if_named("wg_exit").unwrap();
    ki.set_client_exit_tunnel_config(
        SocketAddr::new(
            config.read().unwrap().exit_client.clone().unwrap().exit_ip,
            details.wg_exit_port,
        ),
        details.wg_public_key,
        config.read().unwrap().network.wg_private_key_path.clone(),
        config
            .read()
            .unwrap()
            .exit_client
            .clone()
            .unwrap()
            .wg_listen_port,
        details.own_internal_ip,
    )?;
    ki.set_route_to_tunnel(&"172.168.1.254".parse()?).unwrap();
    Ok(())
}

fn request_own_exit_ip(
    config: Arc<RwLock<settings::RitaSettings>>,
) -> Result<ExitClientDetails, Error> {
    let exit_server = config.read().unwrap().exit_client.clone().unwrap().exit_ip;
    let ident = althea_types::ExitClientIdentity {
        global: config.read().unwrap().get_identity(),
        wg_port: config
            .read()
            .unwrap()
            .exit_client
            .clone()
            .unwrap()
            .wg_listen_port
            .clone(),
        reg_details: config
            .read()
            .unwrap()
            .exit_client
            .clone()
            .unwrap()
            .reg_details
            .clone(),
    };

    let endpoint = format!(
        "http://[{}]:{}/setup",
        exit_server,
        config
            .read()
            .unwrap()
            .exit_client
            .clone()
            .unwrap()
            .exit_registration_port
    );

    trace!("Sending exit setup request to {:?}", endpoint);
    let client = reqwest::Client::new();
    let response = client.post(&endpoint).json(&ident).send();

    let exit_id: ExitServerIdentity = response?.json()?;

    trace!("Got exit setup response {:?}", exit_id);

    Ok(ExitClientDetails {
        own_internal_ip: exit_id.own_local_ip,
        eth_address: exit_id.global.eth_address,
        wg_public_key: exit_id.global.wg_public_key,
        wg_exit_port: exit_id.wg_port,
        server_internal_ip: exit_id.server_local_ip,
        exit_price: exit_id.price,
        netmask: exit_id.netmask,
    })
}

/// called before anything is started to delete existing wireguard per hop tunnels
fn cleanup() -> Result<(), Error> {
    let ki = KernelInterface {};

    let interfaces = ki.get_interfaces()?;

    let re = Regex::new(r"^wg[0-9]+$")?;

    for i in interfaces {
        if re.is_match(&i) {
            ki.del_interface(&i)?;
        }
    }

    ki.del_interface("wg_exit")?;
    Ok(())
}

// Replacement for the setup.ash file in althea firmware
fn openwrt_init(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    cleanup()?;

    let privkey = config.read().unwrap().network.wg_private_key.clone();
    let pubkey = config.read().unwrap().network.wg_public_key.clone();
    let mesh_ip = config.read().unwrap().network.own_ip.clone();

    if !validate_wg_key(&privkey) || validate_wg_key(&pubkey) {
        openwrt_generate_and_set_wg_keys(config.clone()).expect("failed to generate wg keys");
    }

    let ki = KernelInterface {};
    //Creates file on disk containing key
    ki.create_wg_key(
        &Path::new(&config.read().unwrap().network.wg_private_key_path),
        &config.read().unwrap().network.wg_private_key,
    )?;

    if !validate_mesh_ip(&mesh_ip) {
        openwrt_generate_mesh_ip(config.clone()).expect("failed to generate ip");
    }

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        openwrt_generate_and_set_wg_keys(config.clone()).expect("failed to generate wg keys");
    }

    let ki = KernelInterface {};
    //Creates file on disk containing key
    ki.create_wg_key(
        &Path::new(&config.read().unwrap().network.wg_private_key_path),
        &config.read().unwrap().network.wg_private_key,
    )?;

    if !validate_mesh_ip(&mesh_ip) {
        openwrt_generate_mesh_ip(config.clone()).expect("failed to generate ip");
    }

    thread::spawn(move || loop {
        if config.read().unwrap().exit_client.is_some() {
            let our_exit_ip = config
                .read()
                .unwrap()
                .exit_client
                .clone()
                .unwrap()
                .exit_ip
                .clone();

            assert!(!our_exit_ip.is_ipv4());
            assert!(!our_exit_ip.is_unspecified());

            let details = request_own_exit_ip(config.clone());

            match details {
                Ok(details) => {
                    let mut exit_client = config.read().unwrap().exit_client.clone().unwrap();

                    exit_client.details = Some(details);

                    config.write().expect("can't write config!").exit_client = Some(exit_client);

                    // openwrt_setup_exit_tunnel(config.clone()).expect("can't set exit tunnel up!");
                    linux_setup_exit_tunnel(config.clone()).expect("can't set exit tunnel up!");

                    info!("got exit details, exiting");
                    break;
                }
                Err(err) => {
                    warn!("got error back from requesting details, {:?}", err);
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    });

    Ok(())
}

fn linux_init(config: Arc<RwLock<settings::RitaSettings>>) -> Result<(), Error> {
    cleanup()?;

    let privkey = config.read().unwrap().network.wg_private_key.clone();
    let pubkey = config.read().unwrap().network.wg_public_key.clone();
    let mesh_ip = config.read().unwrap().network.own_ip.clone();

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        linux_generate_wg_keys(config.clone()).expect("failed to generate wg keys");
    }
    if !validate_mesh_ip(&mesh_ip) {
        linux_generate_mesh_ip(config.clone()).expect("failed to generate ip");
    }

    //Creates file on disk containing key
    ki.create_wg_key(
        &Path::new(&config.read().unwrap().network.wg_private_key_path),
        &config.read().unwrap().network.wg_private_key,
    )?;

    thread::spawn(move || loop {
        if config.read().unwrap().exit_client.is_some() {
            let our_exit_ip = config
                .read()
                .unwrap()
                .exit_client
                .clone()
                .unwrap()
                .exit_ip
                .clone();

            assert!(!our_exit_ip.is_ipv4());
            assert!(!our_exit_ip.is_unspecified());

            let details = request_own_exit_ip(config.clone());

            match details {
                Ok(details) => {
                    let mut exit_client = config.read().unwrap().exit_client.clone().unwrap();

                    exit_client.details = Some(details);

                    config.write().expect("can't write config!").exit_client = Some(exit_client);

                    linux_setup_exit_tunnel(config.clone()).expect("can't set exit tunnel up!");

                    info!("got exit details, exiting");
                    break;
                }
                Err(err) => {
                    warn!("got error back from requesting details, {:?}", err);
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    });

    Ok(())
}

pub fn init(platform: &str, settings: Arc<RwLock<settings::RitaSettings>>) {
    match platform {
        "linux" => linux_init(settings.clone()).unwrap(),
        "openwrt" => openwrt_init(settings.clone()).unwrap(),
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_wg_key() {
        let good_key = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
        let bad_key1 = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpXk=";
        let bad_key2 = "look at me, I'm the same length as a key but";
        assert_eq!(validate_wg_key(&good_key), true);
        assert_eq!(validate_wg_key(&bad_key1), false);
        assert_eq!(validate_wg_key(&bad_key2), false);
    }

    #[test]
    fn test_generate_wg_key() {
        let mut ki = KernelInterface {};
        let keys = ki.create_wg_keypair().unwrap();
        let wg_public_key = &keys[0];
        let wg_private_key = &keys[1];
        assert_eq!(validate_wg_key(&wg_public_key), true);
        assert_eq!(validate_wg_key(&wg_private_key), true);
    }

    #[test]
    fn test_validate_mesh_ip() {
        let good_ip = "fd44:94c:41e2::9e6".parse::<IpAddr>().unwrap();
        let bad_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert_eq!(validate_mesh_ip(&good_ip), true);
        assert_eq!(validate_mesh_ip(&bad_ip), false);
    }
}
