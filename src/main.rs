mod theme;

use std::cell::RefCell;
use std::io::Read;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pgp_core::{KeyInfo, PgpKey};
use slint_keyos_platform::app_ui2;
use slint_keyos_platform::fs::{self, Location, OpenFlags};
use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
use slint_keyos_platform::navigation::open_qr_scanner;
use slint_keyos_platform::qrcode;
use slint_keyos_platform::slint::{Color, ComponentHandle, ModelRc, Timer, VecModel};

app_ui2!("PGP Keychain");
security::use_api!();

/// App-managed keychain directory on Internal (User) storage.
const KEYS_DIR: &str = "/pgp-keys";

type Fs = fs::FileSystem<fs_permissions::FileSystemPermissions>;

struct CurrentKey {
    filename: String,
    key: PgpKey,
    info: KeyInfo,
}

/// What the file browser (screen 2) is currently picking a file for.
/// Values mirror `Ui.browse-mode`: 0/1/2/3.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BrowseMode {
    Import,
    SignFile,
    Encrypt,
    Decrypt,
}

impl BrowseMode {
    fn ui_index(self) -> i32 {
        match self {
            BrowseMode::Import => 0,
            BrowseMode::SignFile => 1,
            BrowseMode::Encrypt => 2,
            BrowseMode::Decrypt => 3,
        }
    }
}

/// Mutable app state shared across the UI callbacks.
struct State {
    current: Option<CurrentKey>,
    import_location: Location,
    import_path: String, // current import-browser directory, always starts with '/'
    browse_mode: BrowseMode,
    browse_target: Option<(String, Location)>, // picked file awaiting confirm/passphrase
    sign_qr_data: Option<Vec<u8>>, // QR-scanned bytes awaiting passphrase
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone();
    let ui_weak = ui.as_weak();
    let state = Rc::new(RefCell::new(State {
        current: None,
        import_location: Location::User,
        import_path: "/".to_string(),
        browse_mode: BrowseMode::Import,
        browse_target: None,
        sign_qr_data: None,
    }));

    if let Err(e) = fs.create_dir(KEYS_DIR, Location::User) {
        // FileAlreadyExists is the normal case after first run.
        if !matches!(e, fs::Error::FileAlreadyExists) {
            log::warn!("could not create {KEYS_DIR}: {e:?}");
        }
    }

    // Re-scan /pgp-keys and push rows into the KeyList global.
    let refresh_keys: Rc<dyn Fn()> = {
        let fs = fs.clone();
        let ui_weak = ui_weak.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let mut rows: Vec<KeyRow> = Vec::new();
            let mut names: Vec<String> = Vec::new();
            if let Ok(dir) = fs.open_dir(KEYS_DIR, Location::User) {
                while let Ok(Some(entry)) = dir.next_entry() {
                    if entry.is_file && entry.name.to_lowercase().ends_with(".asc") {
                        names.push(entry.name);
                    }
                }
            }
            names.sort_by_key(|n| n.to_lowercase());
            for name in names {
                match load_key(&fs, &name) {
                    Ok(key) => {
                        let info = pgp_core::key_info(&key);
                        rows.push(KeyRow {
                            filename: name.into(),
                            title: primary_uid(&info).into(),
                            subtitle: subtitle(&info).into(),
                            has_secret: info.has_secret,
                        });
                    }
                    Err(e) => log::warn!("skipping {name}: {e}"),
                }
            }
            log::info!("cb: refresh-keys n={}", rows.len());
            let list = ui.global::<KeyList>();
            list.set_status(if rows.is_empty() {
                "No keys yet — use ••• to create or import one".into()
            } else {
                "".into()
            });
            list.set_keys(ModelRc::new(VecModel::from(rows)));
        })
    };

    refresh_keys();

    // Open a key's detail view (shared by list taps and post-import/create).
    let open_key: Rc<dyn Fn(String)> = {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        Rc::new(move |filename: String| {
            let Some(ui) = ui_weak.upgrade() else { return };
            match load_key(&fs, &filename) {
                Ok(key) => {
                    let info = pgp_core::key_info(&key);
                    log::info!(
                        "cb: open-key {filename} fpr={} secret={}",
                        info.fingerprint,
                        info.has_secret
                    );
                    set_detail(&ui, &filename, &info);
                    state.borrow_mut().current = Some(CurrentKey { filename, key, info });
                    show_info(&ui, "");
                    ui.global::<Ui>().set_screen(1);
                }
                Err(e) => show_error(&ui, e),
            }
        })
    };

    // Re-list the import browser's current directory.
    let refresh_import: Rc<dyn Fn()> = {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let (loc, path, mode) = {
                let s = state.borrow();
                (s.import_location, s.import_path.clone(), s.browse_mode)
            };
            let browser = ui.global::<Browser>();

            let mut items: Vec<(bool, String, String)> = Vec::new();
            let mut status = String::new();
            match fs.open_dir(path.as_str(), loc) {
                Ok(dir) => loop {
                    match dir.next_entry() {
                        Ok(Some(entry)) => {
                            if entry.name.starts_with('.') {
                                continue;
                            }
                            // Hide the app's own keychain dir from the import browser.
                            if entry.is_dir
                                && loc == Location::User
                                && path == "/"
                                && entry.name == KEYS_DIR.trim_start_matches('/')
                            {
                                continue;
                            }
                            if entry.is_dir {
                                items.push((true, entry.name, "Folder".to_string()));
                            } else if mode != BrowseMode::Import
                                || entry.name.to_lowercase().ends_with(".asc")
                            {
                                let size = human_size(entry.len);
                                items.push((false, entry.name, size));
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            status = err_msg(&e);
                            break;
                        }
                    }
                },
                Err(e) => status = err_msg(&e),
            }

            // Folders first, then alphabetical (case-insensitive).
            items.sort_by(|a, b| {
                b.0.cmp(&a.0)
                    .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
            });

            let rows: Vec<FileRow> = items
                .into_iter()
                .map(|(is_dir, name, info)| FileRow {
                    name: name.into(),
                    info: info.into(),
                    is_folder: is_dir,
                })
                .collect();

            browser.set_entries(ModelRc::new(VecModel::from(rows)));
            browser.set_path(path.clone().into());
            browser.set_at_root(path == "/");
            browser.set_status(status.into());
        })
    };

    let callbacks = ui.global::<Callbacks>();

    {
        let refresh_keys = refresh_keys.clone();
        callbacks.on_refresh_keys(move || refresh_keys());
    }

    {
        let open_key = open_key.clone();
        callbacks.on_open_key(move |filename| open_key(filename.to_string()));
    }

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        callbacks.on_close_detail(move || {
            state.borrow_mut().current = None;
            if let Some(ui) = ui_weak.upgrade() {
                show_info(&ui, "");
                ui.global::<Ui>().set_screen(0);
            }
            refresh_keys();
        });
    }

    // --- Import browser ---

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        let refresh_import = refresh_import.clone();
        let open_browser: Rc<dyn Fn(BrowseMode)> = {
            let state = state.clone();
            let ui_weak = ui_weak.clone();
            Rc::new(move |mode: BrowseMode| {
                {
                    let mut s = state.borrow_mut();
                    s.import_location = Location::User;
                    s.import_path = "/".to_string();
                    s.browse_mode = mode;
                    s.browse_target = None;
                }
                if let Some(ui) = ui_weak.upgrade() {
                    show_info(&ui, "");
                    ui.global::<Browser>().set_location_index(0);
                    ui.global::<Ui>().set_browse_mode(mode.ui_index());
                    ui.global::<Ui>().set_screen(2);
                }
                refresh_import();
            })
        };

        {
            let open_browser = open_browser.clone();
            callbacks.on_start_import(move || open_browser(BrowseMode::Import));
        }
        {
            let open_browser = open_browser.clone();
            callbacks.on_start_sign(move || open_browser(BrowseMode::SignFile));
        }
        {
            let open_browser = open_browser.clone();
            callbacks.on_start_encrypt(move || open_browser(BrowseMode::Encrypt));
        }
        callbacks.on_start_decrypt(move || open_browser(BrowseMode::Decrypt));
    }

    {
        let state = state.clone();
        let refresh_import = refresh_import.clone();
        callbacks.on_import_location_changed(move |idx| {
            {
                let mut s = state.borrow_mut();
                s.import_location = location_for(idx);
                s.import_path = "/".to_string();
            }
            refresh_import();
        });
    }

    {
        let state = state.clone();
        let refresh_import = refresh_import.clone();
        callbacks.on_import_go_back(move || {
            {
                let mut s = state.borrow_mut();
                s.import_path = parent_path(&s.import_path);
            }
            refresh_import();
        });
    }

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        callbacks.on_cancel_import(move || {
            let from_detail = {
                let mut s = state.borrow_mut();
                let was = s.browse_mode != BrowseMode::Import;
                s.browse_mode = BrowseMode::Import;
                s.browse_target = None;
                was
            };
            if let Some(ui) = ui_weak.upgrade() {
                show_info(&ui, "");
                ui.global::<Ui>().set_browse_mode(0);
                // Sign/encrypt/decrypt picking starts from the key detail
                // screen; return there. Import returns to the list.
                ui.global::<Ui>().set_screen(if from_detail { 1 } else { 0 });
            }
            if !from_detail {
                refresh_keys();
            }
        });
    }

    // Tap a row in the import browser: descend, or parse + copy into /pgp-keys.
    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        let refresh_import = refresh_import.clone();
        let refresh_keys = refresh_keys.clone();
        let open_key = open_key.clone();
        callbacks.on_import_entry_activated(move |name, is_folder| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let (loc, dir) = {
                let s = state.borrow();
                (s.import_location, s.import_path.clone())
            };
            let full = join_path(&dir, name.as_str());

            if is_folder {
                state.borrow_mut().import_path = full;
                refresh_import();
                return;
            }

            let mode = state.borrow().browse_mode;
            if mode != BrowseMode::Import {
                state.borrow_mut().browse_target = Some((full, loc));
                let u = ui.global::<Ui>();
                u.set_sign_file_name(name.clone());
                u.set_field_pass("".into());
                match mode {
                    BrowseMode::SignFile => u.set_show_sign_pass(true),
                    BrowseMode::Encrypt => {
                        u.set_encrypt_sign(false);
                        u.set_show_encrypt_modal(true);
                    }
                    BrowseMode::Decrypt => u.set_show_decrypt_pass(true),
                    BrowseMode::Import => unreachable!(),
                }
                return;
            }

            let data = match read_bytes(&fs, &full, loc) {
                Ok(d) => d,
                Err(e) => {
                    log::info!("cb: import-key {name} err={e}");
                    show_error(&ui, e);
                    return;
                }
            };
            match pgp_core::parse_keys(&data) {
                Ok(keys) => {
                    let mut first_file: Option<String> = None;
                    let n = keys.len();
                    for key in keys {
                        // Never downgrade: importing a public copy of a key
                        // whose secret material we already hold keeps the
                        // secret version on disk.
                        if !key.has_secret() {
                            let info = pgp_core::key_info(&key);
                            let existing = format!("{}.asc", info.key_id);
                            if matches!(load_key(&fs, &existing), Ok(k) if k.has_secret()) {
                                log::info!(
                                    "cb: import-key {name} ok fpr={} secret=false kept-secret",
                                    info.fingerprint
                                );
                                first_file.get_or_insert(existing);
                                continue;
                            }
                        }
                        match save_key(&fs, &key) {
                            Ok(filename) => {
                                let info = pgp_core::key_info(&key);
                                log::info!(
                                    "cb: import-key {name} ok fpr={} secret={}",
                                    info.fingerprint,
                                    info.has_secret
                                );
                                first_file.get_or_insert(filename);
                            }
                            Err(e) => {
                                log::info!("cb: import-key {name} err={e}");
                                show_error(&ui, e);
                                return;
                            }
                        }
                    }
                    refresh_keys();
                    if let Some(f) = first_file {
                        open_key(f);
                        show_info(&ui, &format!("Imported {n} key(s)"));
                    }
                }
                Err(e) => {
                    log::info!("cb: import-key {name} err={}", e.0);
                    show_error(&ui, e.0);
                }
            }
        });
    }

    // --- Create key ---

    {
        let ui_weak = ui_weak.clone();
        callbacks.on_show_create(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let u = ui.global::<Ui>();
                u.set_create_name("".into());
                u.set_create_email("".into());
                u.set_create_pass("".into());
                u.set_create_bits_index(0);
                u.set_create_mode(0);
                u.set_create_account("0".into());
                show_info(&ui, "");
                u.set_screen(3);
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        callbacks.on_cancel_create(move || {
            if let Some(ui) = ui_weak.upgrade() {
                show_info(&ui, "");
                ui.global::<Ui>().set_screen(0);
            }
            refresh_keys();
        });
    }

    {
        let fs = fs.clone();
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        let open_key = open_key.clone();
        callbacks.on_create_key(move |name, email, bits_index, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let name = name.to_string();
            let email = email.to_string();
            let pass = pass.to_string();
            let bits: u32 = match bits_index {
                1 => 3072,
                2 => 4096,
                _ => 2048,
            };
            if name.trim().is_empty() || email.trim().is_empty() {
                show_error(&ui, "Name and email are required".to_string());
                return;
            }

            let u = ui.global::<Ui>();
            u.set_busy_text(format!("Generating RSA-{bits} key…").into());
            u.set_busy(true);

            // Give the busy overlay a frame to paint before the (blocking,
            // single-threaded) keygen call freezes the event loop.
            let fs = fs.clone();
            let ui_weak = ui_weak.clone();
            let refresh_keys = refresh_keys.clone();
            let open_key = open_key.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let passphrase = if pass.is_empty() { None } else { Some(pass.as_str()) };
                let result = pgp_core::generate_rsa(bits, name.trim(), email.trim(), passphrase)
                    .map_err(|e| e.0)
                    .and_then(|key| {
                        let key = PgpKey::Secret(key);
                        save_key(&fs, &key).map(|f| (f, key))
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok((filename, key)) => {
                        let info = pgp_core::key_info(&key);
                        log::info!("cb: create-key rsa{bits} ok fpr={}", info.fingerprint);
                        refresh_keys();
                        open_key(filename);
                        show_info(&ui, "Key generated");
                    }
                    Err(e) => {
                        log::info!("cb: create-key rsa{bits} err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    // Derive an Ed25519 key from the device master seed (GetAppSeed).
    {
        let fs = fs.clone();
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        let open_key = open_key.clone();
        callbacks.on_create_derived_key(move |name, email, account, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let name = name.to_string();
            let email = email.to_string();
            let pass = pass.to_string();
            if name.trim().is_empty() || email.trim().is_empty() {
                show_error(&ui, "Name and email are required".to_string());
                return;
            }
            let index: u32 = match account.trim().parse() {
                Ok(i) => i,
                Err(_) => {
                    show_error(&ui, "Account number must be a whole number".to_string());
                    return;
                }
            };

            let u = ui.global::<Ui>();
            u.set_busy_text(format!("Deriving key #{index} from device seed…").into());
            u.set_busy(true);

            let fs = fs.clone();
            let ui_weak = ui_weak.clone();
            let refresh_keys = refresh_keys.clone();
            let open_key = open_key.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let passphrase = if pass.is_empty() { None } else { Some(pass.as_str()) };
                let result = Security::default()
                    .app_seed()
                    .map_err(|_| "Device locked or seed unavailable".to_string())
                    .and_then(|app_seed| {
                        pgp_core::derive_ed25519(&app_seed, index, name.trim(), email.trim(), passphrase)
                            .map_err(|e| e.0)
                    })
                    .and_then(|key| {
                        let key = PgpKey::Secret(key);
                        save_key(&fs, &key).map(|f| (f, key))
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok((filename, key)) => {
                        let info = pgp_core::key_info(&key);
                        log::info!("cb: create-key ed25519-derived idx={index} ok fpr={}", info.fingerprint);
                        refresh_keys();
                        open_key(filename);
                        show_info(&ui, &format!("Key #{index} derived from device seed"));
                    }
                    Err(e) => {
                        log::info!("cb: create-key ed25519-derived idx={index} err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    // --- Edit operations on the current (secret) key ---

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_extend_expiry(move |days, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let days = days.to_string();
            let days: Option<u32> = if days.trim().is_empty() {
                None
            } else {
                match days.trim().parse() {
                    Ok(d) => Some(d),
                    Err(_) => {
                        show_error(&ui, "Days must be a number".to_string());
                        return;
                    }
                }
            };
            let result = with_secret_key(&state, |sk| {
                pgp_core::set_expiration(sk, pass.as_str(), days, now_epoch())
            })
            .and_then(|new_key| persist_current(&fs, &state, new_key));
            match result {
                Ok(info) => {
                    let expires = info
                        .expires_at
                        .map(|t| format_date(t))
                        .unwrap_or_else(|| "never".to_string());
                    log::info!("cb: extend-expiry ok expires={expires}");
                    set_detail(&ui, &state.borrow().current.as_ref().unwrap().filename, &info);
                    show_info(&ui, "Expiration updated");
                }
                Err(e) => {
                    log::info!("cb: extend-expiry err={e}");
                    show_error(&ui, e);
                }
            }
        });
    }

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_add_uid(move |name, email, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if name.trim().is_empty() || email.trim().is_empty() {
                show_error(&ui, "Name and email are required".to_string());
                return;
            }
            let result = with_secret_key(&state, |sk| {
                pgp_core::add_user_id(sk, pass.as_str(), name.trim(), email.trim())
            })
            .and_then(|new_key| persist_current(&fs, &state, new_key));
            match result {
                Ok(info) => {
                    log::info!("cb: add-uid ok uids={}", info.user_ids.len());
                    set_detail(&ui, &state.borrow().current.as_ref().unwrap().filename, &info);
                    show_info(&ui, "User ID added");
                }
                Err(e) => {
                    log::info!("cb: add-uid err={e}");
                    show_error(&ui, e);
                }
            }
        });
    }

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_remove_uid(move |index, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let result = with_secret_key(&state, |sk| {
                // The packet edit itself needs no signing, but require the
                // passphrase so a casual passerby can't strip identities.
                pgp_core::check_passphrase(sk, pass.as_str())?;
                pgp_core::remove_user_id(sk, index as usize)
            })
            .and_then(|new_key| persist_current(&fs, &state, new_key));
            match result {
                Ok(info) => {
                    log::info!("cb: remove-uid ok uids={}", info.user_ids.len());
                    set_detail(&ui, &state.borrow().current.as_ref().unwrap().filename, &info);
                    show_info(&ui, "User ID removed");
                }
                Err(e) => {
                    log::info!("cb: remove-uid err={e}");
                    show_error(&ui, e);
                }
            }
        });
    }

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_change_passphrase(move |old, new| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let new = new.to_string();
            let new_opt = if new.is_empty() { None } else { Some(new.as_str()) };
            let result = with_secret_key(&state, |sk| {
                pgp_core::change_passphrase(sk, old.as_str(), new_opt)
            })
            .and_then(|new_key| persist_current(&fs, &state, new_key));
            match result {
                Ok(_info) => {
                    log::info!("cb: change-passphrase ok");
                    show_info(
                        &ui,
                        if new.is_empty() {
                            "Passphrase removed"
                        } else {
                            "Passphrase changed"
                        },
                    );
                }
                Err(e) => {
                    log::info!("cb: change-passphrase err=wrong-passphrase ({e})");
                    show_error(&ui, e);
                }
            }
        });
    }

    // --- Export / delete ---

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_export_key(move |secret, dest| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let s = state.borrow();
            let Some(cur) = s.current.as_ref() else { return };
            let (loc, loc_name) = match dest {
                1 => (Location::Airlock, "airlock"),
                _ => (Location::User, "internal"),
            };
            let kind = if secret { "secret" } else { "public" };
            let armored = if secret {
                pgp_core::export_armored(&cur.key)
            } else {
                pgp_core::export_public_armored(&cur.key)
            };
            let path = format!("/{}-{kind}.asc", cur.info.key_id);
            let result = armored.map_err(|e| e.0).and_then(|text| {
                fs.open_file(path.as_str(), loc, OpenFlags::CREATE)
                    .and_then(|mut f| f.overwrite(text.as_bytes()))
                    .map_err(|e| err_msg(&e))
            });
            match result {
                Ok(()) => {
                    log::info!("cb: export-key kind={kind} dest={loc_name} path={path} ok");
                    show_info(&ui, &format!("Exported to {loc_name} {path}"));
                }
                Err(e) => {
                    log::info!("cb: export-key kind={kind} dest={loc_name} err={e}");
                    show_error(&ui, e);
                }
            }
        });
    }

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        let refresh_keys = refresh_keys.clone();
        callbacks.on_delete_key(move |filename| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let full = format!("{KEYS_DIR}/{filename}");
            match fs.remove(full.as_str(), Location::User) {
                Ok(()) => {
                    log::info!("cb: delete-key {filename} ok");
                    state.borrow_mut().current = None;
                    show_info(&ui, "Key deleted");
                    ui.global::<Ui>().set_screen(0);
                    refresh_keys();
                }
                Err(e) => show_error(&ui, err_msg(&e)),
            }
        });
    }

    // --- Sign file (detached binary .sig next to the input) ---

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_sign_file(move |pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some((path, loc)) = state.borrow().browse_target.clone() else { return };
            let pass = pass.to_string();

            let u = ui.global::<Ui>();
            u.set_busy_text("Signing file…".into());
            u.set_busy(true);

            // Same trick as keygen: let the busy overlay paint one frame
            // before file read + signing block the event loop.
            let fs = fs.clone();
            let state = state.clone();
            let ui_weak = ui_weak.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                let sig_path = format!("{path}.sig");
                let loc_name = match loc {
                    Location::Airlock => "airlock",
                    Location::Usb => "usb",
                    _ => "internal",
                };
                let result = read_bytes(&fs, &path, loc)
                    .and_then(|data| {
                        with_secret_key(&state, |sk| pgp_core::sign_detached(sk, &pass, &data))
                    })
                    .and_then(|sig| {
                        fs.open_file(sig_path.as_str(), loc, OpenFlags::CREATE)
                            .and_then(|mut f| f.overwrite(&sig))
                            .map_err(|e| err_msg(&e))
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(()) => {
                        log::info!("cb: sign-file {name} ok path={sig_path} loc={loc_name}");
                        state.borrow_mut().browse_mode = BrowseMode::Import;
                        ui.global::<Ui>().set_browse_mode(0);
                        ui.global::<Ui>().set_screen(1);
                        show_info(&ui, &format!("Signature written: {sig_path}"));
                    }
                    Err(e) => {
                        // Stay on the browser so the user can retry (e.g.
                        // wrong passphrase, USB unplugged mid-flow).
                        log::info!("cb: sign-file {name} err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    // --- Encrypt / decrypt (output written next to the input) ---

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_encrypt_file(move |sign, pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some((path, loc)) = state.borrow().browse_target.clone() else { return };
            let pass = pass.to_string();

            let u = ui.global::<Ui>();
            u.set_busy_text("Encrypting file…".into());
            u.set_busy(true);

            let fs = fs.clone();
            let state = state.clone();
            let ui_weak = ui_weak.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                let out_path = format!("{path}.gpg");
                let loc_name = loc_name(loc);
                let result = read_bytes(&fs, &path, loc)
                    .and_then(|data| {
                        let s = state.borrow();
                        let cur = s.current.as_ref().ok_or("No key open")?;
                        let sign_with = if sign {
                            match &cur.key {
                                PgpKey::Secret(sk) => Some((sk, pass.as_str())),
                                PgpKey::Public(_) => {
                                    return Err("Cannot sign: no secret key".to_string())
                                }
                            }
                        } else {
                            None
                        };
                        pgp_core::encrypt_bytes(&cur.key, &name, data, sign_with)
                            .map_err(|e| e.0)
                    })
                    .and_then(|cipher| {
                        fs.open_file(out_path.as_str(), loc, OpenFlags::CREATE)
                            .and_then(|mut f| f.overwrite(&cipher))
                            .map_err(|e| err_msg(&e))
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(()) => {
                        log::info!(
                            "cb: encrypt-file {name} ok path={out_path} loc={loc_name} sign={sign}"
                        );
                        state.borrow_mut().browse_mode = BrowseMode::Import;
                        ui.global::<Ui>().set_browse_mode(0);
                        ui.global::<Ui>().set_screen(1);
                        show_info(&ui, &format!("Encrypted: {out_path}"));
                    }
                    Err(e) => {
                        log::info!("cb: encrypt-file {name} err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    {
        let fs = fs.clone();
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_decrypt_file(move |pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some((path, loc)) = state.borrow().browse_target.clone() else { return };
            let pass = pass.to_string();

            let u = ui.global::<Ui>();
            u.set_busy_text("Decrypting file…".into());
            u.set_busy(true);

            let fs = fs.clone();
            let state = state.clone();
            let ui_weak = ui_weak.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                let out_path = strip_pgp_ext(&path);
                let loc_name = loc_name(loc);
                let result = read_bytes(&fs, &path, loc)
                    .and_then(|data| {
                        with_secret_key(&state, |sk| pgp_core::decrypt_bytes(sk, &pass, data))
                    })
                    .and_then(|plain| {
                        fs.open_file(out_path.as_str(), loc, OpenFlags::CREATE)
                            .and_then(|mut f| f.overwrite(&plain))
                            .map_err(|e| err_msg(&e))
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(()) => {
                        log::info!("cb: decrypt-file {name} ok path={out_path} loc={loc_name}");
                        state.borrow_mut().browse_mode = BrowseMode::Import;
                        ui.global::<Ui>().set_browse_mode(0);
                        ui.global::<Ui>().set_screen(1);
                        show_info(&ui, &format!("Decrypted: {out_path}"));
                    }
                    Err(e) => {
                        log::info!("cb: decrypt-file {name} err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    // --- Sign QR-scanned data (armored signature shown as a QR code) ---

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_start_sign_qr(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if !state.borrow().current.as_ref().is_some_and(|c| c.key.has_secret()) {
                return;
            }
            let opts = ScanQrOptions {
                header_title: "Scan data to sign".into(),
                message: "Point at a QR code (or animated UR) holding the data to sign".into(),
                ..ScanQrOptions::default()
            };
            // Blocks while the system scanner modal owns the screen — the
            // same synchronous pattern KeyOS's authenticator app uses.
            let scanned = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) => data,
                Ok(Some(ScanQrResult::Ur2 { ur_type, data, .. })) => {
                    log::info!("cb: sign-qr scanned ur={ur_type}");
                    data
                }
                Ok(_) => {
                    log::info!("cb: sign-qr cancelled");
                    return;
                }
                Err(e) => {
                    log::info!("cb: sign-qr err=scanner {e:?}");
                    show_error(&ui, format!("QR scanner unavailable: {e:?}"));
                    return;
                }
            };
            if scanned.is_empty() {
                show_error(&ui, "Empty QR code".to_string());
                return;
            }
            log::info!("cb: sign-qr scanned n={}", scanned.len());
            let u = ui.global::<Ui>();
            u.set_sign_qr_info(format!("{} scanned byte(s)", scanned.len()).into());
            u.set_field_pass("".into());
            u.set_show_sign_qr_pass(true);
            state.borrow_mut().sign_qr_data = Some(scanned);
        });
    }

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_sign_qr(move |pass| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(data) = state.borrow().sign_qr_data.clone() else { return };
            let pass = pass.to_string();

            let u = ui.global::<Ui>();
            u.set_busy_text("Signing scanned data…".into());
            u.set_busy(true);

            let state = state.clone();
            let ui_weak = ui_weak.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let result = with_secret_key(&state, |sk| {
                    pgp_core::sign_detached_armored(sk, &pass, &data)
                });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(armored) => {
                        log::info!("cb: sign-qr ok sig-chars={}", armored.len());
                        let img = qrcode::render(
                            armored.as_bytes(),
                            Color::from_rgb_u8(0, 0, 0),
                            Color::from_rgb_u8(255, 255, 255),
                        );
                        let u = ui.global::<Ui>();
                        u.set_sign_qr_image(img);
                        u.set_show_sign_qr_result(true);
                        show_info(&ui, "");
                    }
                    Err(e) => {
                        log::info!("cb: sign-qr err={e}");
                        show_error(&ui, e);
                    }
                }
            });
        });
    }

    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        callbacks.on_close_sign_qr(move || {
            state.borrow_mut().sign_qr_data = None;
            if let Some(ui) = ui_weak.upgrade() {
                ui.global::<Ui>().set_show_sign_qr_result(false);
            }
        });
    }

    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// Key persistence helpers
// ---------------------------------------------------------------------------

fn load_key(fs: &Fs, filename: &str) -> Result<PgpKey, String> {
    let full = format!("{KEYS_DIR}/{filename}");
    let data = read_bytes(fs, &full, Location::User)?;
    let mut keys = pgp_core::parse_keys(&data).map_err(|e| e.0)?;
    Ok(keys.remove(0))
}

/// Write a key into /pgp-keys as `<KEYID>.asc` (secret armor when present).
fn save_key(fs: &Fs, key: &PgpKey) -> Result<String, String> {
    let info = pgp_core::key_info(key);
    let filename = format!("{}.asc", info.key_id);
    let armored = pgp_core::export_armored(key).map_err(|e| e.0)?;
    let full = format!("{KEYS_DIR}/{filename}");
    fs.open_file(full.as_str(), Location::User, OpenFlags::CREATE)
        .and_then(|mut f| f.overwrite(armored.as_bytes()))
        .map_err(|e| err_msg(&e))?;
    Ok(filename)
}

fn loc_name(loc: Location) -> &'static str {
    match loc {
        Location::Airlock => "airlock",
        Location::Usb => "usb",
        _ => "internal",
    }
}

/// Output path for a decrypted file: strip a trailing .gpg/.pgp/.asc,
/// otherwise append .out — never equal to the input path.
fn strip_pgp_ext(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    for ext in [".gpg", ".pgp", ".asc"] {
        if lower.ends_with(ext) {
            let stem = &path[..path.len() - ext.len()];
            if !stem.is_empty() && !stem.ends_with('/') {
                return stem.to_string();
            }
        }
    }
    format!("{path}.out")
}

/// Run an op against the current key, which must have secret material.
fn with_secret_key<R, F>(state: &Rc<RefCell<State>>, op: F) -> Result<R, String>
where
    F: FnOnce(&pgp_core::SignedSecretKey) -> Result<R, pgp_core::PgpError>,
{
    let s = state.borrow();
    let cur = s.current.as_ref().ok_or("No key open")?;
    match &cur.key {
        PgpKey::Secret(sk) => op(sk).map_err(|e| e.0),
        PgpKey::Public(_) => Err("Cannot edit: no secret key".to_string()),
    }
}

/// Persist an edited key over its existing file and update app state.
fn persist_current(
    fs: &Fs,
    state: &Rc<RefCell<State>>,
    new_key: pgp_core::SignedSecretKey,
) -> Result<KeyInfo, String> {
    let key = PgpKey::Secret(new_key);
    let info = pgp_core::key_info(&key);
    let filename = save_key(fs, &key)?;
    let mut s = state.borrow_mut();
    s.current = Some(CurrentKey {
        filename,
        key,
        info: info.clone(),
    });
    Ok(info)
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

fn set_detail(ui: &AppWindow, filename: &str, info: &KeyInfo) {
    let detail = ui.global::<Detail>();
    detail.set_filename(filename.into());
    detail.set_title(primary_uid(info).into());
    detail.set_has_secret(info.has_secret);

    let uids: Vec<slint_keyos_platform::slint::SharedString> =
        info.user_ids.iter().map(|u| u.as_str().into()).collect();
    detail.set_user_ids(ModelRc::new(VecModel::from(uids)));

    let mut rows: Vec<DetailRow> = vec![
        DetailRow {
            label: "Fingerprint".into(),
            value: group_fingerprint(&info.fingerprint).into(),
        },
        DetailRow {
            label: "Key ID".into(),
            value: info.key_id.clone().into(),
        },
        DetailRow {
            label: "Algorithm".into(),
            value: algo_line(&info.algorithm, &info.size_or_curve).into(),
        },
        DetailRow {
            label: "Created".into(),
            value: format_date(info.created_at).into(),
        },
        DetailRow {
            label: "Expires".into(),
            value: info
                .expires_at
                .map(format_date)
                .unwrap_or_else(|| "Never".to_string())
                .into(),
        },
        DetailRow {
            label: "Secret material".into(),
            value: if info.has_secret { "Yes" } else { "No" }.into(),
        },
    ];
    for sub in &info.subkeys {
        rows.push(DetailRow {
            label: format!("Subkey ({})", sub.usage).into(),
            value: format!(
                "{} · {} · {}",
                algo_line(&sub.algorithm, &sub.size_or_curve),
                sub.key_id,
                format_date(sub.created_at)
            )
            .into(),
        });
    }
    detail.set_rows(ModelRc::new(VecModel::from(rows)));
}

fn primary_uid(info: &KeyInfo) -> String {
    info.user_ids
        .first()
        .cloned()
        .unwrap_or_else(|| info.key_id.clone())
}

fn subtitle(info: &KeyInfo) -> String {
    let mut s = algo_line(&info.algorithm, &info.size_or_curve);
    s.push_str(if info.has_secret {
        " · secret key"
    } else {
        " · public only"
    });
    s
}

fn algo_line(algorithm: &str, size_or_curve: &str) -> String {
    if size_or_curve.is_empty() {
        algorithm.to_string()
    } else {
        format!("{algorithm} {size_or_curve}")
    }
}

/// "AAAA BBBB …" — fingerprint in 4-char groups so it can word-wrap.
fn group_fingerprint(fpr: &str) -> String {
    fpr.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn show_info(ui: &AppWindow, msg: &str) {
    let u = ui.global::<Ui>();
    u.set_message(msg.into());
    u.set_message_error(false);
}

fn show_error(ui: &AppWindow, msg: String) {
    let u = ui.global::<Ui>();
    u.set_message(msg.into());
    u.set_message_error(true);
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn read_bytes(fs: &Fs, path: &str, loc: Location) -> Result<Vec<u8>, String> {
    let mut file = fs
        .open_file(path, loc, OpenFlags::READ_ONLY)
        .map_err(|e| err_msg(&e))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| "Read failed".to_string())?;
    Ok(buf)
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Epoch seconds -> "YYYY-MM-DD" (UTC), via the days-from-civil inverse
/// (Howard Hinnant's algorithm) — no chrono dependency.
fn format_date(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn location_for(index: i32) -> Location {
    match index {
        1 => Location::Airlock,
        2 => Location::Usb,
        _ => Location::User,
    }
}

fn join_path(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn err_msg(e: &fs::Error) -> String {
    use slint_keyos_platform::fs::Error::*;
    match e {
        NoMedia => "Not connected".to_string(),
        AccessDenied => "Access denied".to_string(),
        FileNotFound => "Not found".to_string(),
        FileAlreadyExists => "Already exists".to_string(),
        FileInUse => "File is in use".to_string(),
        InvalidPath => "Invalid name".to_string(),
        other => format!("Error: {other:?}"),
    }
}
