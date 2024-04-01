// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::Engine;
use ipnet::{IpNet, Ipv4Net};
use once_cell::sync::{Lazy, OnceCell};
use std::{
    net::{Ipv4Addr, SocketAddr},
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
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
    handshake_age: u64,
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
fn wg_disconnect() {
    WG_STOP_TUNNEL.store(true, Ordering::Relaxed);
    println!();
    println!("Exiting!");
}

#[tauri::command]
fn wg_connect(
    private_key: &str,
    peer_public_key: &str,
    internal_ip: &str,
    endpoint: &str,
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

    adapter.set_config(&interface).unwrap();
    match adapter.set_default_route(&[Ipv4Net::new(internal_ip, 24).unwrap().into()], &interface) {
        Ok(()) => {}
        Err(err) => panic!("Failed to set default route: {}", err),
    }
    assert!(adapter.up());

    let stop = Arc::clone(&WG_STOP_TUNNEL);
    let _thread = std::thread::spawn(move || {
        println!("Waiting 10s to ensure the handshake occurs...");
        std::thread::sleep(Duration::from_secs(10));
        println!();
        println!("Printing peer bandwidth statistics");

        'outer: loop {
            for _ in 0..5 {
                if stop.load(Ordering::Relaxed) {
                    drop(adapter);
                    break 'outer;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            let stats = adapter.get_config();
            for peer in stats.peers {
                let handshake_age = Instant::now().saturating_duration_since(peer.last_handshake);
                window
                    .emit(
                        "wg-statistics",
                        WgStatistics {
                            up: peer.tx_bytes,
                            down: peer.rx_bytes,
                            handshake_age: handshake_age.as_secs(),
                        },
                    )
                    .unwrap();
                println!(
                    "  {:?}, up: {}, down: {}, handshake: {:.1}s ago",
                    peer.allowed_ips,
                    peer.tx_bytes,
                    peer.rx_bytes,
                    handshake_age.as_secs()
                );
            }
        }
    });
}
