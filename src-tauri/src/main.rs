// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::Engine;
use ipnet::{IpNet, Ipv4Net};
use once_cell::sync::{Lazy, OnceCell};
use regex::Regex;
use std::{
    net::{Ipv4Addr, SocketAddr},
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
    vec,
};
use tauri::Manager;

static BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
static WG_STOP_TUNNEL: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static OF_AUTH_TOKEN: OnceCell<String> = OnceCell::new();
const OF_AUTH_API: &str = "https://api.fabric.ophelia-matrix.net/auth";

#[derive(serde::Deserialize)]
struct AuthResponse {
    response: AuthInfo,
}

#[derive(serde::Deserialize)]
struct AuthInfo {
    iv: String,
    encrypted_auth_token: String,
}

#[derive(Clone, serde::Serialize)]
struct WgStatistics {
    up: u64,
    down: u64,
    handshake_age: String,
}

#[derive(Clone, serde::Serialize)]
struct WgPing {
    latency: i64,
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .setup(|app| {
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wg_connect,
            wg_disconnect,
            get_of_auth_token,
            init_of_auth_token,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn get_aes_key() -> &'static str {
    return env!("OF_AUTH_AES_KEY");
}

fn extract_ipv4_addr(input: &str) -> Option<&str> {
    let regex_ipv4: Regex = Regex::new(r"(?<ip>(?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9])))").unwrap();
    regex_ipv4
        .captures(input)
        .and_then(|cap| cap.name("ip").map(|ip| ip.as_str()))
}

#[tauri::command]
fn init_of_auth_token() -> Result<(), String> {
    if OF_AUTH_TOKEN.get().is_some() {
        return Ok(());
    }

    let resp = reqwest::blocking::get(OF_AUTH_API)
        .map_err(|_e| "Cannot connect to Auth API!")?
        .json::<AuthResponse>()
        .map_err(|_e| "Cannot deserialize JSON!")?;

    let key: &Key<Aes256Gcm> = get_aes_key().as_bytes().into();
    let iv = BASE64_ENGINE
        .decode(resp.response.iv)
        .map_err(|_e| "Cannot decode IV!")?;
    let encrypted_auth_token = BASE64_ENGINE
        .decode(resp.response.encrypted_auth_token)
        .map_err(|_e| "Cannot decode cipher text!")?;

    let decrypted_auth_token = Aes256Gcm::new(&key)
        .decrypt(Nonce::from_slice(&iv[..]), &encrypted_auth_token[..])
        .map_err(|_e| "Cannot decrypted token!")?;

    let token_str =
        String::from_utf8(decrypted_auth_token).map_err(|_e| "Cannot convert token to string!")?;

    OF_AUTH_TOKEN.get_or_init(|| token_str);

    Ok(())
}

#[tauri::command]
fn get_of_auth_token() -> String {
    return match OF_AUTH_TOKEN.get() {
        Some(token) => token.to_string(),
        None => String::from(""),
    };
}

#[tauri::command]
fn wg_disconnect(window: tauri::Window) {
    WG_STOP_TUNNEL.store(true, Ordering::Relaxed);
    let _ = window.emit(
        "wg-statistics",
        WgStatistics {
            up: 0,
            down: 0,
            handshake_age: "N/A".to_string(),
        },
    );
    println!();
    println!("Exiting!");
}

#[tauri::command]
fn wg_connect(
    private_key: &str,
    peer_public_key: &str,
    internal_ip: &str,
    endpoint: &str,
    server_internal_ip: &str,
    allowed_ip: Vec<&str>,
    window: tauri::Window,
) {
    let private_key = BASE64_ENGINE.decode(private_key).unwrap();
    let peer_public_key = BASE64_ENGINE.decode(peer_public_key).unwrap();
    let internal_ip: Ipv4Addr = internal_ip.parse().unwrap();
    let endpoint: SocketAddr = endpoint.parse().unwrap();
    let mut allowed_ips_ipnet: Vec<IpNet> = Vec::new();
    for i in allowed_ip {
        allowed_ips_ipnet.push(i.parse().unwrap());
    }

    WG_STOP_TUNNEL.store(false, Ordering::Relaxed);

    println!("Connecting to {} - internal ip: {}", endpoint, internal_ip);

    //Must be run as Administrator because we create network adapters
    //Load the wireguard dll file so that we can call the underlying C functions
    //Unsafe because we are loading an arbitrary dll file
    let wireguard = unsafe { wireguard_nt::load_from_path("wireguard.dll") }
        .expect("Failed to load wireguard dll");
    //Try to open an adapter from the given pool with the name "Ophelia Fabric"
    let adapter = match wireguard_nt::Adapter::open(wireguard, "Ophelia Fabric") {
        Ok(a) => a,
        Err((_, wireguard)) => {
            println!("Cannot open adapter, creating new one...");
            //If loading failed (most likely it didn't exist), create a new one
            match wireguard_nt::Adapter::create(wireguard, "Ophelia Fabric", "Ophelia Fabric", None)
            {
                Ok(a) => a,
                Err((e, _)) => panic!("Failed to create adapter: {:?}", e),
            }
        }
    };

    let mut interface_private = [0; 32];
    let mut peer_pub = [0; 32];

    interface_private.copy_from_slice(private_key.as_slice());
    peer_pub.copy_from_slice(peer_public_key.as_slice());

    let interface = wireguard_nt::SetInterface {
        listen_port: None,
        public_key: None,
        private_key: Some(interface_private),
        peers: vec![wireguard_nt::SetPeer {
            public_key: Some(peer_pub),
            preshared_key: None,
            keep_alive: Some(5),
            allowed_ips: allowed_ips_ipnet,
            endpoint,
        }],
    };
    assert!(adapter.set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix));

    adapter
        .set_config(&interface)
        .expect("Can't set config for Wireguard adapter!");
    match adapter.set_default_route(&[Ipv4Net::new(internal_ip, 24).unwrap().into()], &interface) {
        Ok(()) => {}
        Err(err) => panic!("Failed to set default route: {}", err),
    }
    assert!(adapter.up());

    // Poll network status and report
    let stop_wg = Arc::clone(&WG_STOP_TUNNEL);
    let window1 = window.clone();

    let _thread_wg = std::thread::spawn(move || {
        println!();
        println!("Printing peer bandwidth statistics");

        'outer: loop {
            for _ in 0..5 {
                if stop_wg.load(Ordering::Relaxed) {
                    drop(adapter);
                    break 'outer;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            let stats = adapter.get_config();
            for peer in stats.peers {
                let handshake_age: String;
                if let Some(last_handshake) = peer.last_handshake {
                    handshake_age = format!(
                        "{:.1}",
                        SystemTime::now()
                            .duration_since(last_handshake)
                            .unwrap()
                            .as_secs_f64()
                    );
                } else {
                    handshake_age = "N/A".to_string();
                }
                let _ = window1.emit(
                    "wg-statistics",
                    WgStatistics {
                        up: peer.tx_bytes,
                        down: peer.rx_bytes,
                        handshake_age: handshake_age.clone(),
                    },
                );
                println!(
                    "  {:?}, up: {}, down: {}, handshake: {}s ago",
                    peer.allowed_ips,
                    peer.tx_bytes,
                    peer.rx_bytes,
                    handshake_age.clone()
                );
            }
        }
    });

    //Ping server and report
    let addr = extract_ipv4_addr(server_internal_ip)
        .expect("Server IP should not be None!")
        .parse()
        .unwrap();
    let timeout = Duration::from_secs(5);
    let stop_ping = Arc::clone(&WG_STOP_TUNNEL);
    let window2 = window.clone();

    let _thread_ping = std::thread::spawn(move || {
        let data = [0; 32];

        'outer: loop {
            for _ in 0..5 {
                if stop_ping.load(Ordering::Relaxed) {
                    break 'outer;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            let result = ping_rs::send_ping(&addr, timeout, &data, None);
            match result {
                Ok(reply) => {
                    println!("Ping {}: latency={}ms", reply.address, reply.rtt);
                    let _ = window2.emit(
                        "wg-ping",
                        WgPing {
                            latency: reply.rtt.into(),
                        },
                    );
                }
                Err(e) => {
                    println!("{:?}", e);
                    let _ = window2.emit("wg-ping", WgPing { latency: -1 });
                }
            }
        }
    });
}
