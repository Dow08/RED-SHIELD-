use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

mod recon;

// Garde le handle du moteur (sidecar) pour le stopper à la fermeture de l'app.
struct EngineChild(Mutex<Option<CommandChild>>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    // Recon natif (mobile) : cartographie / scan / énum web sans moteur Python.
    .invoke_handler(tauri::generate_handler![
      recon::discover_hosts,
      recon::scan_ports,
      recon::web_enum
    ])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      // Démarre le moteur RED SHIELD (sidecar) lié à 127.0.0.1:8787 — encapsulé,
      // invisible pour l'utilisateur (aucune URL/navigateur exposé).
      // DESKTOP UNIQUEMENT : sur mobile, le moteur est embarqué côté client
      // (ui/src/mobile/offline.ts), il n'y a pas de sidecar Python.
      #[cfg(desktop)]
      {
        let sidecar = app.shell().sidecar("red-engine")?;
        let (mut rx, child) = sidecar.spawn()?;
        app.manage(EngineChild(Mutex::new(Some(child))));
        tauri::async_runtime::spawn(async move {
          use tauri_plugin_shell::process::CommandEvent;
          while let Some(event) = rx.recv().await {
            if let CommandEvent::Stderr(line) = event {
              log::info!("engine: {}", String::from_utf8_lossy(&line));
            }
          }
        });
      }
      Ok(())
    })
    .build(tauri::generate_context!())
    .expect("error while building tauri application")
    .run(|app, event| {
      // Arrêt propre du moteur quand l'app se ferme.
      if let tauri::RunEvent::ExitRequested { .. } = event {
        if let Some(state) = app.try_state::<EngineChild>() {
          if let Some(child) = state.0.lock().unwrap().take() {
            let _ = child.kill();
          }
        }
      }
    });
}
