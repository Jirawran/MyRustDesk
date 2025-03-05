use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIEAAABxCAYAAADyMsBJAAABgGlDQ1BzUkdCIElFQzYxOTY2LTIuMQAAKJF1kc8rRFEUxz8GjRiNYqFIk7Ca0Rg1mY3FiKGwmBllsJl580vNj9d7M2myVbZTlNj4teAvYKuslSJSsmZLbNBznlEjmXs753zu995zuvdcsIQzSlZvcEM2V9CCAb9jPrLgsD5hoUusB19U0dWZ0ESYmuPthjozXrnMWrXP/Tta4gldgbom4VFF1QrCk8LTKwXV5E3hDiUdjQsfCzs1uaDwtanHKvxocqrCHyZr4eAYWNqEHalfHPvFSlrLCsvL6ctmisrPfcyX2BK5uZDEXrFudIIE8ONginHG8DKET7wXFx4GZUWNfPd3/ix5yVXEq5TQWCZFmgJOUYtSPSExKXpCZoaS2f+/fdWTw55KdZsfGh8M46UfrBvwWTaM933D+DyA+ns4y1Xz83sw8ip6uar17YJ9DU7Oq1psC07XofNOjWrRb6lezJJMwvMRtEag/RKaFys9+9nn8BbCq/JVF7C9AwNy3r70BZ4YZ/9i1e7kAAAACXBIWXMAAAsTAAALEwEAmpwYAAAgAElEQVR4nO19d7wdVbX/d+8pp92em5seQkJoIQkpRCCoVEFABOKTYFCKSFURUFHwKVhQLCDv6VPRh9hAARUQfbQgNRCSSCcB0nu5uf2eNjN7/f6Y2Xv2zDnn9psEP7/1+dx75sye2bP2Wt9Vdpl9GN4DtO2nUxP5Dq+WCbeWmUYtN80mZvAxIIwDx0R4xZHgrIaB14AZNeBIMcaTEMQJxACAgUCMgzHmQVCRQN0kRBeE10FgbZybOwG+kcjbAqLN5IlmCLdDsERbOm20j/zsSmdvy2G4iO1tBspRy51T090dxvvh5o9lpj0XwH5gPANmpDhnCQAWGBkgxsAAxnj5dhALWkjaSeYDInZGkCD/DiIQPDC4RCiARJ7I6yTB1gunsIwZicWr21c9c9xN8Iar/Xua9ioIOh6abbW+2zEZnjiCm9YsxvnBjGEKGJsAxpIAY4wzFiozJAb4qiSAMaaUysJCIPhgkYNKpN3UUzkJQUQ5w+YbuMneIeG9Sa77mmDmCnOn2DDy6yvd/sphb9MeBcGqr06yLZs3mlXmNI7iWTDMD8GwJnFuGkxyQoG+gu8UKFl9kSyzqC1rFwfAiKuUAh8QrVu7Wz4++F4eNYwxGAkOxqN1kBAued5a4Rb/zmzzXsNka4lZbU0XvlLss4D2Eg07CNruPdLo3N42R+TznyQYxxiWPY4xVgtu2OHD41rTvmscsuA/gXwMlF6C0KKlKql8ufQuLPAmYBpoygAsODKShgJAyaUEEBERhMuAFvKc9V4h/7Rwjd//snP1Gzfd1KOr2Ws0LCDYeMukes+jY7hhnAiDncgNcwrjVqL0saQdocwxi5wste7w6rL1aB6+5+dAq1x7AoMCSwQA8kbptaQ3oDI6JkB4bo48912QeAye94STpWcn3rA2W3rx3qEhA8GSs5us5GjW2LBf5kYwYwE3rXowxrgUYVnJa9+DS6THD4+lgsOoT+T7A7BAR0LWGWuOHj00n8AitWnEQvcOBGEj4MFMcS0sBfmIHob0Z8ZYUP8IRESCvGI7ueLX9qjMzZmmVEfqxCV7NY8YFAjoXrBtmycdUCjwyxk3T+AGnwpupIAw7oIoEB6LhPTw4aWul2LWLeur5EvVdZqX978yBZYwUWTRe4AgJJRmnkGkgJXmKIkBFB7qXqGkSXqGqoGGAJAQ3YB4RxSKj4gc/WTHxtXb5t6x50PGgECw/rsTG4n4B5jBLwCM47lpZ4BAUcoqEUZZFd81UwvMLGKVjPkuVVq19Aq62UaApAWOmBWXNFJ5ez3GU8mFKhENqjaTHMyIZYH644NPYgAEaVmndkH0oxTNBAjP6RaO9w8I97fFLvfpyd/c0Fm+NUNP/QLB5tsOSDn5/JfIsz7N7cQYMGZycOYLOLQxCv6H8VY7rxldTw9X6pXhIAAHQWb/FMZj3U2zcvXGEwodeuXPMAZw24Bhc92dR60+khRGA4zMD1i8WEtopZMKrycC4EAUthXbcz8cn83+zPje7mEfj+gVBG/ceyjLvNs5m2BdyRg/CdwYyw2DR7ysHu+17/I0C5RHAmC8XD5PgetGNC6zICgQRbUUO1aZvVJS1NsoXhiLdguDa3VPJL8YCQ7DNvxmaQqNOAPNtFUuQ2Feo4NEOTjoA1UaGmL3EAmPPHeLcN1H3M7sT/b/1tbXMUxUEQTv/mh/E23edCNpfIVx62zGDTN6o+ablRstzfqYVi6fKAMB05RLJC8KBCoA8oLYSYGQiPzrAHACiPsWzhjAOPcBxhgY98/5xyiDVj1ERGM2AwADsNJmVI+6svQ2aiAq5+aDSypcUPkUCw4EEUF4BVFw/0wmfujtFG/s/4PVQ5pIloCAALbph/u/3+liP2CWOY1xI8MCjnz3G/rb0P1TRLnybNgiFkE5gvgpXP+PRJhrBzjwa6JY3z3uzikqsIgFBoBkDGAmh5lg4DYH45p71yUg8cwYrIxZGh8obE+JQ4p5BwoOQs8RyUwjaU3ZPCZyMmSQiLqFU/xXsbl4+ZTvr3+zzJ0DIgWC1n/ONFuWtJ8CMq4E+Ad5kOXHpeEP0foWXsbAIi2MnBaA5xHgkQ8AIWuWUtFjdtQ6pXeIJH8R4ZFKNNRQMjQFsFBz3GBgJoNhcvAEBzdZJHqYSQOGxWPKJejKL2e9CBJi0m+sEBZQcjrkv1xo0B/LAAjhZkXRfcLLFm7v3Go8PeN/1w0qb2AvX9jI0w3WWLPGvoOY+SHOLUNadXhV2AAGADzwCJK5gOGIHoXPtrT2sAX6hZoYSMZk3ytwOw0GBq/QHTUdgci8EEW0g1IBxsAiw4nEBTcAI2PCTHAYCQ4rZaiHqVyAEBl4CuslTamsdLBIu08BXgmshDktbwjFEx/ijtRNnuN2Zf9spuwvjb/unc0YIPGGg5PfMKozbwL2KYxZBgVulYTfQBWfRSA18q1axmndfZMIrLwg4OVduDkPwhE+ICgoBwBBWpz36wP552EkkDj0Ixh9+QMYccp1StGybkLIj6pDSk3KOHie5E+1R/Eh+Sd4DqHY5qDQXICXE/AKAkQx/hTPsr3+ge6ViPRy/T6pRArbGmg1cq1AhF+9LeEz9XYSGDMssypzDjHjlbc/O+LqAYPAsO3jGec1YJypB0hlKTDoFkuqXAFDEIRD8AoCTs6DVxQ+81K5WoNVo6A1OGgxr5+I6vPvwcgF30GmaRJq5pwNMCMAkS7gqEDC5yCqaAXcECxRIIQKMVImQECxw0WhxYHb7YUeLDIiSGF1mrIi5YgBVMpL41/Jg3Q+StsWMR4FPAlwAsAZ48YI4vaCf54Oo2d1lydTEAkSAHissZIryWzgf5VXlAj3BIQjQoSHsvA/tfPhxE/QXZT1JzJIzb8U1mGnI13biGTCn2Zgpg0jXQ+nc1cwYKS7X4TuFSy0luAj7G7655gUGvmtYIDyLGbSgJkwlLDJJTiOB8CDYTOYVSZkcqyLJS4qdVbLD5hSmHapHFCLjS2osZAgw9XXPUQ8buThyiBd1lXKVl/IBJEXsX4ZDwWBcQYVd4FIP1t4wu/CeYFyFUvh4I5qih7sgrolGSOnIvXhG8GbDkTCtlCdSUUYZHYVQLtCy1IdA9KUQVGZqudA3UOkCy8qSCtlloa34Ho3T/DyRTCLwaoywQ0WWqP8YGE+EO/haI/UOVPGESa7VPne6K2QD4qI1RPZY5+CKHdLb2SCyJUNZkFXjgT5yBfhII7PFwGC+QAQ0iswTRkB83Flaczrwk8csQjW0ReD2RkwBtRURQEAAMyw1LOAEEBxpVP0n+oZSL7V0HMkMQXMlAFmoCwA5LEAgDzByxVhpA1/LoFrM5dluo8lSgcA0mWp803RW2KKRpRlvw5teN4fSvByJcLrI5kgFMIYHUJLPYSFAvH79DIOhFYYtjUADYOfvIV+QQGDEYGl65E68cswDjrB72oyhvraKnCuT9JIPjQL1RYRSEHyRApCACjmQl4hs38qEbZSAPnphl1lBryix9gteXG7XDhdgF1jwUzF+NXcuwwFFCsv48k1AyHVHVDhS6svKnEWJsoA4FBHifD6SJyId0cTEfjCUA0HyCN4RQHhhQqhEvRq8UuEHkBP/kgQWN0EpM/7DfiBJyhPkU4mYJmRAUlF5LmhxoXPm3SlqSnzcMA3l6F21um+u1e9DETcu+odKP78k1bSCPnTARAkw5HkTSXDADxCobWIfHMRoijC8si10exfOWrd40hZkZZ8y2fq6A2YjPQmdO9DRF4RAwaBCbBOIs1itfguvKBBQmjuNQAIg1KGjm8iUkP2KjEK2mEfdAISJ30ZLFWn2pewLFSlkxUZJLcYzbQBgDE0HPcZNJ50BbidRGLM1KjF636ZtDZJBQXWZgY9gjDrRqQbKvmOhweJSS8vkM0Vkag1YWaMUiuP8KSNWSmDCUc+yw0/KucHRMYpYg7Et4+iaKsoxF7IBKhVIStIqf0Gh5YfPjDsHTBNIPGhD9UjkEDhJhIzToV13BcAOxPc7yujOpMKF2uUIeEUo61mHPXvPx8jT70azLAAAPaoKaH16JrQvZMuYEGwqm3lvkOLl+Wh8vVyVV+svNDqwOnykGy0wAwZCvznSeMJvkUFBW24vEJKp9iWhleCNJ9vbtHuSjLsjUwGdJCAZr2kDcaUGUIP/unqV9YHVnoxAfasBT4Agt6FTHKqUknYVvkwoMhzI12tuqPPweizvxa5xKodFQ1P5IOM5NBnyLT/xxlMO+zpqHZr7jbiHeLlQOCiw0Ov4CG7XSBRZ8FIB93NctYt26/JiUoONHmqQwq9E8IVkT4oiWCxDT0LsjKZYG4LCU7gQU/Yk/EpSMBUGh6fINAPSTEqGfRvMZA67goYsxciEnCIwbKMsr2BOMnZRSLAHjkJTaddW3INT9eFESCSq4T5g+5NTMvP7gGE7l96g3LJoV4uPYB+LE85hNyuAux6C1bGjAw3R0ayRXl5EgVJtfKw8j9F65A8hYZLhjA29irMCmSSMNuUixP+oI9EKgvQp9t8FLUUrU0XGjeRmPtx8NkLQdwIgMHUoEsmlewxDEhiVhIkADNVg/0+9wcYVfUl13A7FSibwthZ4r6gzNCuiuUC0qL15A9lyiPKr1xeaHYgcgKJERbCiS2NEfVBsVBKiA6uSZ7171q5LCJ4hXaxo4IIeyUOQa0gAnnhqJ/K5mWDgwb6mTMQGZLQXag2fGvPPQfmBz7r98NIayQBpmH0mAzqZNaOAgDUzPkIrPoxZa9hhgWSAJU8aLzpFmvY3B8h7yn7D4QQKVeeQtYbTRZVeAjyhWKni9z2IsijSH2hjKmk7rJ/0PjXQhRp30mQk23vGvByNC6cbAu5wdCxfJgIG6RcpBSCFHfQoAiDAcfWYafBPOpikN5TVkAA6moyfWawZubJIEEo7FiLztcXg9wKrwQG4JTCiUz4IFSAYRsq79EBElcQxcr1rim08si9crwhULCT9dC9OQfhipjHkfVospPyls9XIAkBprydNuLqGzAKhpXI91moMTIBtptICMAwIr5GjayRYkz3XYSwXKUMRODjpsE84RqQlQi7ZSzICAgwTQ7btvrM4IjjPw1m2tj9+K+w8eeXIrXfTIw550YkJ0zzF4gAIOGGPAIRfqTlsKCcWywUtug5+QsnbqLehEQfy4ngOUB2awGp0Qlww+ckfCZF4rw/pxIyHJm4kwfhWF0oX090e115TXn9I05GuhUiSMHjrkhEhVISa2MDMKyqEfaZt4CsVAgUyWhwXF2Vkjlon6nhA5/E5OsfxsRLfw6nfSfWfP9j2HLnF+B2t/psFHNRAEi3rMdXIhi2AS7nQ4TuzgGUA0DM20W8he4dtfvLlbt54XsER7kmJduSnELJFpHySGiWspcO26NOxit1Mnsnnjyktt1znA7VQOX2owz4DYOKn0o42uhc4vRvAOmGkNEYEAyDoyrde4+gHBmpalTPOBEH3rQYo8/6MrrX/Atrbj4TXauWwG3bFSqdNHcK+MIOBG5nzECYscEfDRAqP4got/R6JSehuet4uQjLRZHQtTkfTE/HAEexv5KBqjKAA8J1Gp7XQqmqAXsCBgBvXjXhJRLmEREzJxYOV8nv5coJAGNIvG8R+AevDCuVY+DBPwaG2poM6qr7ng/0RF53G9bdfgGy619DsmkK8tvelYyFH5I9+JNjqZGJ8N0IACqPiQtdKwdi12veIzp0W6GconUbSY7MuCTCDl+lrndU3jLEMe27lG2hNXv/wf+98T/6Ib4IcQAgp+vFCDqFbBk0C9PQri3MAAHm+MPBj7k06q6kAFVVhFTC7jeDTstWdL3xFNzO5tACABiZOkz5yv0YfcbVPgCozHg/wmMYiABA7+2E1h8DAIVtV95CXq8BxPeM8d5EKC9VNwFuVqB7c6F0wUvEm6CkLYBedyjn4Pv6fgtWIw4AjNg/I+5INk4KUmgPjzECbsI47rMg7s/HVgKCaZhI9CMhlGTWNmH7H7+Odd85FTsfuCVSxriJptM/h7ELvw4YtpJKueyfmzxUaJlyPZ6r+B+zbtKy/zB8atavQiSVrzu4zulykW8ulngQ/TlScOVGMvWuOIjgdWZf6bdgNeIA4Ar7afI8J4ICyIZFYRdfamZ/4BJg1MGakZYHQn+6hToxw0TDCRfD7diNlid+ifW3nInC9tWRaxpPvAAN8z8WWrLelQoE7L9JVGZwKBbPo0qPWWPEShCtTyosMuIYtW6VIwDI73ZQaHOi5Xr4KAsEmQyGPJAnPDNtLBuQcAPiADDzF9tbmME74g1W06/SPWnjBiQIPFUPNv10xW0lIHDGkE5qb6b3k9JTZsNI1oBgILfhdWy4dSGc5k3hBYxj3HnfRO0Rp/nP1F1mMP1sWjxq0drgUMQa9bERIDpZROH1ZcOD7iVFzLo1A5LluR1FeAWhletyjoe30u6svxOC13HPz3bIhGhApK2KoO0lCY4SQhT9AR+wj7sclKwtq3z92LLkGr2BUWL8wZh0/UOY+PnfoPGUK2BWj8DmO64AiXC5PTMtjD//ZqQmzYTsi8vBFWZzDcyIKDRu/RL8oXsv9RZRgFCp+4+vio73JoL7hUvo3OgPJpW4/OD+6HlEwgoRIIreqpuU/xgYqSk8xsQmImNaICttnaC+AQSpFTvGuMNAh37YFzLC2UFf+SxynLCsPs0TVCLGTdiNE2A3TkDmoKMw8oxr4XW3Ap6LYATGb0xVPabecC82/+5G7P7n3aohhsFLEz4d0L1k/z2Wa14nXq7+UOb64Pmi4HuE9JhEKPfgmYz58lOToRRcoa1L9BzvpQELNiDlCZhB76hGqNUusmHaMGYQc60jPg4w/5UuORZQySOkUwMPBZXIyNSDWaX1cjuFiRd9D5OvuRPpqXN9QJpcWWhJMhbP/pVLj3qLXscSYoNP+nsR5a7XXX2+xYHT7YY8Se8kPZUA9N6EWrkkSBTbvRcGK0sFAlHMPS8iQUi7Sgkm+GolgclHh5f0BAQGJBP97xUMihhD7eyTcNCNf8W4hV+FmaqKKaNMrJXgLzf4o5cTKid/sXxCKTT24krcpYMIXRvzEEWNN+jXUOx6BHkNHHjuusGKS4HATtW+KBwnX9JgiQeNieRJV0FYKZ9hWUEFIKTsxKBCwWBp1OmXYdKX7oc95iDN0hAqq4x7LwsATaFAGQBIQPVUrs1V6G9BEQHCIdVtVB4Iet2hXapzrpclEgNeRyBJgWDcwbVbOaO18iGyG6J3uSAIPFULOuhYBGd6BcIe9wJxYgyJMVMx8fN3I33IBwOAx5K7Mq67z9m/NlQdBxDKlas5jShAQITcriKKHW7YxdXqVGFAq88rOhvatqB5sCJSIKi65BXXMJ1/kue3TjUcAUMBMvmYQ0BWRmm5NyAMZIBoOIinajD2gttgJKuj7l1eELd+aOU9ZP9AHACh2VIZZZLmXsv1TnI7woW1ctV2bGWxKnfa8o8e99zuQe9VEFk4b9UkHgWRV5LgSPQBMGZ8GOBcKT/grSIQDKP0XYK9RUaqBhOvvU+z6EABsbECpQDd4rVyFf8BZZ0Rb6FZu/KkPZTr3sLpduF0umGPRD0HoVcAQK5X8DzvnqGQS0RDXq6wEgzR9xAQKhRGAjT5SGjA7BEIjAFGmRdK9iZ53W2l7hoxsKty3SvEE7qw/1/OW8QXppSdmdTr0/KTzg05f7YxNlOr5xZe0du+49XcW0Mhk6gnqKraBrewuXRli/9pHTgfZKfhu7hAeEBlIABl3yraWyQKWWz+5edCAOixVvMA8YSupPun5wdACID4XIKudGjHet0qRITH5BIKrU4k4ZQkn+3lvdc+vCo3JDuvR9Z7H/j9jdmXF6UfB0sGg0aaOgngU4/RdmkLB4UI4XsE8piCvQt5hQ3IeyIv1wWvux3kueB2Eka6BjwxsHUIPu8CubUvY+dDt8Jt3RFad4nCpFZLw0Olcl2hqpwZgGGAmRashrGwp86COfZAmI1jwaobwFLVgBnkSm4RIpeF6GiB17wFzoZVyL31EortO5FsMv0BMb8JkWXmXi7/3MAFEqWSRf88nbrT6Speykw7pS+bZ5wBI/dXAugLEMDQp+6hyHcjv3U1dj9zP9qWP45C8xYwEqGyGINZMwKpcVORmngI0pOmITn+QJhVteBWAsyywbhsCkG4DsgpwMt1I7t6BTpXPIjcupc1iy6T/MW8Q+jmg1pLkjto4cQfWU1MnYP0vNNg7j8DrHoEkK4BzHD6vKL3hL80w8p1wBwzAfb+kyB2rgPPbwc3ihBt2+G17YRcmyw8t0gF9kSvgu0jlYDgL2N3v3HG6qa1IEzT2SQyQJmG4Hv5YeI4EMw+JIVtyx7B5j98G4Wdm/wXTYIxUQk+uVbQbW1GZ1szOt54ISjg4KYNZifATQvghj98LQjCc0DFIkQhByvNYGfMWLxGqFCg55k/IOxO6tZOAKwkkgccjuSM42EffgJYbVO47lJrIwWNUUv5Ad9TUrDGsHk9zHf+AnP7I4BTDLb4Ef4LwA4BLgFJw98HwiWIgrOua0fxjd7V2zcqa6Yvf6rhp8JLXRE9a8C+4QnAsAPlByuHVA0sMknEgpnDiWNHln2w192B7X/7GXY9eTe8jlaQv9GBshZ9BY0i/UvEqqLn9AK7yoSV9l1v2YWh2jPjbyVHrB/a9WCoOmYBqj76ebBMHcAMqHEVjddyQNCbQcKDseJnSDb/DcJx/FXJDkIABGAgFxCOf87/FC557PdkdF552P/sGvRG2WVB8K/zas70vKq/MLkilABj1BQYl/1GTSf1BQhV6SQmjCkPAp1EIYfWFx7GlvtvQ2HHRoT9I0Bt8hRJPuNveOmI0PYkAGBlTNhVVjT5k/XFAKCqKgcAQeCZWtScehkSs04Crx+tXqtTrMZcfCUgyOdQ23Zg27/ACp1AvgU8uxW8812ge6va8Et6A6EAQQoM5FKHcMW95Hg/nHn3lrd7FXQFKu8JPtlY7eT5Jm5ZtbIVifedDTrlGrVeEKgEhDAPyKSSFT1BOfKynWh5/kFs+u034WW7AITuUx6HMQIaABjs+lFITToU3E6idemj/jQzAVbagF0VJGEiVFSl+K+XSzDwdC3Sc09G9VnX+kldhBcMCghhMygEZ1cbaMNLYGsfBWt9F5Rt0UKE7xXII80zoBOu+DJ54p5Z921p77PAA6qYtS07p+7HYOmr5EXJj3wRYs5Z6q6+eIR0MoH9xjWVrV8U8yg2b0GxZTvcjhZ4XW0QxTzAOIrNW7Fr8d1wu9o1KSGWWflkjRiNSZ+5GdXT3ofdzz6IjXfeCK9QVO/0mUkTieogHMStv1L2r3kLe8IhaLj0xzAax5ex/JCZIQWCvE54QCEL9u5TEM9+L8wJnDBceJGwQStdxz133gPbXy0r9ApU8ZVgq8a+zekQFwM8AwagbnRogwT1QomfB/ol0WQRcL3SPRad9mZsve827H7qPrj5LADyu5Rl4jkibzmHwmaMo+rguRj14fPRcMwZYIaJ7rWvY+P/3givWPSfH0QU4WkWplu//CgHACIYVXWoO+tqpOZ/DHKbe4Kc4/fr9nM7PzBFN3D3X3NTIYux4C3p6H3+L7QhDG9OAax5A6h5DdC2FqxjIyjbDHIdsGQN4LTJpdN+d4IF8g6MkkCHcG48s+wjY28qeuJ/5v9je5/eSqoIgoThbHO5tYYEn0ECQLLGR6raddzHMlPWoR/7zLmerwlyHbQ8/yB2Lb4HnauWgzwnolyKuHddSaQJLWC4ugETPnU9mk46F/pvEGy7/6c+AGLeQgQ7qKpqe8v+AVhN+2Pk1b+CMWKc4jDMQ9iQACG4Ckx4oO42sLf/gcS2e4BCNpYYhpbOOCC3EWIMfg8jAAO4/8c8VkOMfmSBHf7CyaMuO+rRHb0mjhVBcMjPW4vLF2T+Cl4zg8AAO+lbgg4ESBUypTSZDxABJAS6N67C5rtuRMerz0CtjJEuhaIiUUKLnvYHSriBptMuxNgFV8JuGB0pz216F7uf/7tSZlgHAa5Q/FRM/rTy6uMXoe7sq8GSVeo8AwOxHoAQnOsPEBgDqGUrzLfugJV7GazYCUEEweG/Ns8oYvFyAwkmn838TwkGJj1zeN95DOygF05oOvOoxTu3VdIz0AMIAMCoydxRaHU+yy17hGDBtu+IAUHzCEqRwbFY9wpW/eZL8Lo7pDRDV0/6KQq9v1BSDZ4FJMfsh/Gfuh4jjjmjLJ/Ni++DcIIRVKXX8BlCILTCcoM/ALiZQO1HrkDNhz4NGCbK2KwCgjojgRDoqq9AgFMEVj6A2tY7IVwXRAQRKDzw7sFOclLJWl0KFOpCqNd+Aw/BggoYwzwC+9vzxzYtnP/UzugSbY16BMGsX+/cuuxj9Q8IIS5iREwpCmU8AsWA8Mr/oeuP35SFSvdMO4YmrBAUmrsGQ3LcZEz7wcMwq0v3JQAA8lx0vBWsuJbz9Ionvz5yBWCw6KJZ9UyfkRHnfQOZ+WeHcZuCjbx1hQZACLHQNyBIBDAAVMgi9cZ3UBT16Kz+D8AT4IVd4O0r0b11Lbq3ZFHoLMLNuv5mYQ75G4doO8cwzsANBm5xGCaHYXOYCaMkXwjCxBzmsYef+8DIGcc8s6vsz/P1slcMwFjxdyD7k/Acm0Bqq/uKoYEI7PXH0XXPTZqmNKHrCgqkF6YHFHoDAKNOPR/7XfR18GS6In/kOnBad4ahQAEorNvfl5FVHPwZdcXtSM09BdAtFirZ6gUImoNTQJCyKw0nPJEGjroF1bYJyzRgGlzNtIpiAc7u7cjv2ISOlf/C9sfuRfe6lWoGUy12kcvgYquZrbSJVH0CZsLQun0MYHQQCMufnd94yvufb94al2GvIDAzjS85zS1vIt81yxdtD0AggO1Yg+57vwv7wHmwps5DuqEJVZkkWpc9jo5Xn4EoFCLuWksQlAfglo3RZ3wGE86/Hoz3vF0veS6czrZobFfVB3HSg/8DGToABEkUVFQAABJISURBVIEn02g8/9tIzz3Fv0W32BDZEYUCYbmyfB0ULPQi8j4AsAwTCdtEOmnDqDCpxu0EEmP2g1nTgOyGd+C0bPO9qA6CwHvJJFef5S10Oih0OGAcsBIm0iMS4Ab328LYdBDdvnhOzSdPWNER6TX0CoLD79qQW3Z21edER/MzFOxsVAkIEB6QbUf6Px8GJfzVR97al7D1L7chv21DTEu6uwxdHREwZsHnMGHRtYj+All5IuHBy2a1HIIidRMAzxHgphEdHSSg/uxrUHXk6WGoKkkAQ28A6EAIu3e9ASFhmajOJGFw3qd3L3Kb1uDNr38MXRs2A55XqviSdxgDPoN8gQRBOIBXKCLXUUQiYyFZbcMwOYhhgWlYbUuOxCVHvxg64F5BAABzp3ctebWrdRtA48LJolIggBvw9p/jewXPg/uXW9C19CE9TCsFMe0YmsLGL7waExZ9EX2SWFABua6ybooWgSEYYk0aSnAEhoYzLkftCedBV2hZIJSx7L4AIZmwkE5asMw+bjxOhN3P/Q1v33YdnNadWgiAtvgkHNwSHnWYCb4sWZ/8R83o1EsG563CFWa+rTimY3vumHyHc7woiGn59mJNrq2IVK2NVE2CMY5FRbfhQaDlYfnoPkoaePlbi75LZ934FTk6IXUkf+MoWhmB/voD5Jb8VVMGItl/uLFj8I8x1M87CQd97ddgRp+wCQBwO1ux7NyZEIW8soxItQCYyZCq819YJQGkps7B2Ot+DWanFH+Qalb3U0ldOsRChxZdYGMaHNXpRN+VL2txHbQufRTFlu3Ib12DzndeRse6Tcjv2kFwXCZDAjNYZ7rB/sXOVa3fO2u92+PehffWs9qacVWLvKL3ZafbHW/YhlFVnwTnvJuKYtqxr7VuAPoBgrcun5IqfvKuNlE7JpggrwAEEqDFdyL3yP9GHQDFDqTfDIRYe9iROPS794OZ/VuY6na1Y/l5c+F2tkd6KpIzqaFUQwIMDNbIcZjwrQdhpGsj/JGu5BgQdNYrAQEAMqkEkrY5JEvsSQh42S4nu3n1xpcuPGEKuQJW2ng2OTL5yaP+LGNr3+ilDzbauzZnj/dc8RPh0ZRMXRKmyf503CttC4HY8rKe6NCfrckZrZv/WN4CQknxneuQe+K3WvYt/6A+43sEmNV12P+K7/YbAADADBNGsiqMj+VeCyf4L36CMHLRf8LI1AX9a60eBjXohRi41XUMEQXLQ9MwUFuVQioxuNftIu3iHMww2l+/4cIxwvGcmvGp20bNqjuxvwAAgHlPNxdPW5N9xMnnD05lrC90NGfb893ux56cXnc60A8QAID38gNXG+1bi1EgkDwCK2SRu+sGkONEFKDHMwWcIM4xZmDK536I9P6H9rdtAHwQmDX1YaYMLcxoYHCLHqqP/iiq5pyoKXUAQEAUCJbJUVuV7Lf7742IiFbdfInIbVmfrB6b+s8jH9hxzaG3ryvbz+8rLdgB9+S3u2532p39nLz7VD7r/GHxITWN/QLB4V/7Uwtf/eJtEF5kaFe539cWw9mxvgQAanMH/+JIZps+YAbq55044IZx04JVP1KrmrTXwUJvY42YiFGf+nppAOwDEFAOCGBIJSzUVPW8N/NAqfOtZeu3Pf5wfc3EzOVH/23nLb3f0XdamEN7bU3qFKcorioWxJn9XgpcNePYm4xsSzeAEiAUnvuzUr7eX1efqpvjn2J2Egd84dbBLSLlHDXT5kXcv3yePjg08syLYVTVl7XsOBAAX8kymWUID+RAXCppIZ20+55U9ZM2//kXZv2UzLfe/fu2Xw5H/R98s9X96KbcXazo3ttvEEyeNS9HL953DXMLAEJlG1vfhrNhlaYE0pRA2gCHPEUYeexZyEweWBjQacT8UyIzhRR5NpA+4DA0nXFBjy5eB0JkXYT/EQFCKmkhNbyv13m5dS/8ee7d2751XjbewR5aOmVzvmNALwXkn/vdncbWVWulxokIhXtvkd8i/VmVQMqEUIvVI0/6+FC0A5nJhyJ9wLSwfvkJgBjDuPO/HCo56tPLeIDgs0wBA5CyLSSH99U6Evnub4872vricD5EpwGB4Kj7d7nJ0aNPI6dIAIHnO+FsWR0mf5H9doJDrRNOBKTGT0Xt9CMH3wIAYAyjTzsP8veY5DOICFZNA2oOP1rF7dCyw7ivJ4qxaqFdCdsyhv0FW/K8R3gy8+0xl7w27L+WLmnArwcdNHv+KvPVR+8nzwPraAG5nrJyf7wbodWXeed/0sU39GlYuK/UMO94cNMK85HgeY0nLgBPRTfNqgQE/3xpoggwmAYf0BZ8/SEvl9vCDGMRY2xIfxC7NxqUFqykcYHRtTtLLVsQ/kCWNpwikzPtO4hg1jagdub8wTy6hFLjJ2PksR+NZKVEwPYH7kJutf/b0pE+fvCvtEuIEiAYnPlJ4HBlgQC8QsEh11nAGGsdvqeUp0GBYNrCq7J85VMXu6tfKcSTP73fruK0fxrGhEPQXhhib8cYDrz+x7BqG8OQRASRz+Odr38abmtzcFn/gZBMWP3ej7k/JByHqFi42KqpXTpsD+mBBj3C8dnRK9/seuE5j5h5XLhdVWyCSJ4JMJGacwK6JsxEVaYPP3/TD2KGCeG5aFv2dGTuwGlvQ/vSpzDi+DPAk36/Pt63Lx0bAMAYEpYJ2xragaA4tb/28kOZSZO/OqwP6YEGHZQPu2MbpQ7O3UJe8UnVIQC0pFDvJvqHxsRDQIKwbWcLhAwjQ0TjP34paqbPi40YAt1r3sLrF5+MrjdXqGtZrMcQzxEMzpCwhw6k5ahz5ZsbWLbrgmF9SC80JJnZ3DsgIIrXevlCu3T9kTlwHRCCwEeOA4HQnS1gw9adQ8GCIiOVxrTv3Am7bmRk8IgIyG/ZgDcuPR27/vEnyD0QewJCYgi9VJzIc9H17tv5bX+57/i6Y44b8M/ZDQUNaaB7an5qIYzkXZzzRMmIoUYNtzwMt9Z/KYUxhrFNDRjZUDt0jBChdfmzeONL58Hp6oSaTQx4YdxAzZz5mHT59UgfMrt0zgH+j3MMBwg63nwFW+//PVqWPt/Z/sY7J5+6qWXQW9ANloYUBM8dl7S8onE38cQCpgddmSQEUm649TE46frIVPTEsSNRX1s1lOxg5xMPYuU3LoeXz2krl0JUmqkkRp/2Hxhx2nlI7n8weCKlWB2KZJCEgNPSjOyGtWhbvgTbHrwXXe+uBAA4HfmrT9tZ/PGgHjBENOQp7x8Ph9mUyCznieRMtdRLPib4PuJHj8Kpqoe+JsHgHFMmjhnajS+J0L32bSy/6MNwO9tKwgPjQDJjA4YFs7YBI8/4FBpP+wSSI0fDHsSsYGH7Vuz4x5+x/eH70L1ujb+uMlhabtc3YtzF165ZeeOVB5+xDXt0PKASDUu/56kj7fmCEv/HbasaZcJCw3f/Cjd4u0cHAucck8Y1oaaq8urigVDn26/j3R9ej9blz4VD2gFP3OSwk+H6Q8ZNJMZORGrCFCTHTERi1HjYjU0wa+rAEykwxkGeCy+XhdvZjuLuZhR2bEVh53YUtm9GduMGFJv9X6dTA2amiRFHH4vRZ54LNmFKdvsTj86a9cWvvDOkjRwEDVvnd/Es61yeSN3BDDP08YEhjrjhV3D2m1H2lXbOGPYb14TaIfqFFEmikMfa/7kZWx74PZzWFsUPQLBSltpWp+J+hJGJMWjXRL2LLGfcRGLkKNTNPRr7X34trP0OwO5du6ntiUdvPPT88785pI0bJA3jGBiweLb9XzyR+WzYKSeAGOou/BrE0f7bRGWBwDlGN9ahaUTdkPNU2LEVG377E2y651egor/8nXMOO2VGBrdKN7Twv4STYeXLWSKJphPPwPhPXITMlINg1dShrSuL7q4sOp9dfNe6y8+96NSW4Z0Z7C8NKwieOspOC8+6B9z+iBqAIyBz7Jngi64PJ3XKAAEARtRVY2zTiGHZCzG3ZSN2Pv4gdj//JNpfWwEqdMK0jND6oblzhBYfKScGu74RVVMPRdWhM1A35yjUzTkSVq3/tlQuX0R7Vzdc10P+zVffyr/5+tHTr7q63/sHDDcNKwgA4MnZ5gjBEs9w0zqEMf8l9sQBM5H80s/9n2JEz0CwTANTJo5Bchgnb8jz0Lp8CVqXPIaOV5Yiv20ThOMBJII5EQaAA5zDqh+B6oOmo3b2kah/3weQnji5ZPZRCIHdbZ3IFYpgYCiue3fHAfOPHl324fsADTsIAOCJ2WwiWOpJbiamAP529NW3/h2UrOpxkwtJpmGgoa4aY5sa9gS7INeBV8iDnOBVd8bATAs8kQS3KoPREwLtHd3ozhVUaHFbmvPZF587cvpnLunXxhF7koZ3UDyg325D+6dGsZUkcCrjRpo8B4nG0cAkf1VRb0AQRMjmC2jr6IZpGrDtoVvVW44YN8DtBIxkGkYqDSOZBrcTYEZ5cTmui86uHJpbOlAoOmpZutfa4nQ+/dixMy+/ckXZG/cR2iOeQNKTR1bNF0X2f8wwqgGg7hfPgYIfrigPhNisX3BsWQYmjx89rCGiL+R5As2tHcjm/aV2+uAXOUXqfOi+M2Zcdc3DPVSxT9Ae8QSSrphqbS5mnW1E/GSAW6lDZ4NGjoM+e19uXb/uFRhjEILQ0taJzu48hCAkbGtAO6cOhFzPQ0dXDi3tXWhp70TRcUt4Js9D9tknr5t+yWV37RGmBkl71BNIemx64jJmWLemph+ZSn7xJyDOewFC1EPEX33jnKOuJoO6miokLBOmaQxZuBBCwPUECkUHXd05ZPP+nkjxvEXtzZDPUe6lJV85bNGi7w8JA3uA9qgnkHRKl7cimRAb3ZbtH06O28/E+KnRxR3og0fQFwcSIVdw0NbRhZb2LrR2dCsLtQYAiELR8WN8Wwda2jrR1tGNru4cHDcc5S2bxBIh/9KSHx32iU/c2K8H7mXaK55A0iMH2dcYTWNubvjB/QmR9mcRy+UA/rE6qvwyrL4sLAAVY4Bp+htCGMGGEOH0sb9xhRDkW7zw4HlCTTZV5qM0iYVTpPzyJT95a+G5V3287Nzpvkt7xRNI+v1u74VFiexuw8mfaMycbwav/wwqNMSBALDApXsoOh4KRQeFooN80UG+4KDoOCg6LlzXg9C2hCldcFqZD1EoUn7F0p8UFi686qT3GACAIVpUMhgqZt1ftD30+8/QS4/5qzxii1Ojx8EFKP8yLAUXRVY3acvcETlGrJ6woKSeHvkgFF9d/q3pC8/5/Nz3IACAvewJAOCeTtDdreK1cwqbWpMzjzqZqmp1Q1NeobexhL6Ehr7VExb05hEo1+3lVyy9bvo5H795QI3fR2iv5gRxWjy79vja2x95XNSO4ANT4J4DAhXyIvfMkxccfslnfjeYNu8LtNc9gU6/3VZYd9Hkxq3GhANOIzuxbwFBq8vrbHfdFUs/PvPTF/1psG3eF2if8gSSXrr9e+fwI47/naiqs/YpIDAGd9vmzuwzT82Z99WvDOqXyvcl2idBAACvP7Y4U7CsHWLE6My+AgRvw9pd2VXvTJ13xWf2uengwdBe7x1UoukfOqHbXfHsPL5+5frwFbf+ZPtD12sgIVB8dcWywqsvH/zvBgBgH/YEkpZcd1nCPuKE58XkQ+eoPY32oEegYoGc5UvuO/z88xey92gXsDfa50EAAC++8w43n3/2a+Lwo29S07l7AAjU2eF5ry0/bcb5FzwWrIf5t6T3BAgkLf3p7aca02bfRw2j/OXIwwUEArzN65vdd95eOOfySxcPa6P2AXpPgQAA/vmVizPV71+wksbvPwGMDzkQyHNJrHl7ZXH5i/Pm3fSt7j3Rpr1N7zkQAMCyX/y8iiUSP6DD5l4KO8GGCghUyJP7r6XfXXPhBV97r00CDYbekyCQtPSn/32RMW3Wf1NDU3pQQABA2za1FJYv+ej7vvzVIfv52fcKvadBAAAv3HCtbR1x7Os0+aAD+w0EAABBvLrs8dnnLvzQHmR7n6J9dpygr3TUd35UXHvmRw5mK577Dst2eX3p/1MwTkC7d+Xdpc9dVr9p5Sl7g/d9hd7znkCnp754bV3VcSe9QeMmjZNdybIewXWJNqx521367LHv+873duwVZvch+rcCAQC8/Ohi212z6nL2vg/cCjvJgRgQujtdb9mz55ijxz0062ML9om3gvc2/duBQNJLP/7xPDZp8h8w+eADGGOA6xBb+/bLxdWrLzrqui/tsy+C/H8aBlp2+61Xvvr0c7uX/dd/Xbi3edlX6f8Bv/gasnBfhuAAAAAASUVORK5CYII=".into()
    }
}
