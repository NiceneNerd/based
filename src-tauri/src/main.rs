#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]
use keystone::{Keystone, Arch, OptionType};

#[tauri::command]
fn apply_patches() {

}

#[tauri::command]
fn validate_patch(patch: String) -> Result<String, String> {
  let ks = Keystone::new(Arch::PPC, keystone::MODE_32 | keystone::MODE_BIG_ENDIAN).unwrap();
  let result = ks.asm(patch, 0);
  Ok(String::default())
}

fn main() {
  tauri::Builder::default()
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
