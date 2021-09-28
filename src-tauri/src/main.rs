#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]
use keystone::{Arch, Keystone, Mode};
use serde::Deserialize;
use std::{
  fs::{read, write},
  path::PathBuf,
  process::Command,
};

#[derive(Debug, Deserialize)]
struct Patch {
  addr: u32,
  asm: String,
}

fn wiiurpxtool_path() -> PathBuf {
  let exe = if cfg!(windows) {
    "wiiurpxtool.exe"
  } else {
    "wiiurpxtool"
  };
  let path = std::env::current_exe().unwrap().parent().unwrap().join(exe);
  if path.exists() {
    path
  } else {
    std::env::current_dir().unwrap().join(exe)
  }
}

fn get_decompressed_path() -> PathBuf {
  dirs::home_dir().unwrap().join("U-King.elf")
}

fn decompress(input: PathBuf) -> Result<(), String> {
  let decompressed = get_decompressed_path();
  if !decompressed.exists() {
    let output = Command::new(&wiiurpxtool_path())
      .args([
        "-d",
        input.to_str().unwrap(),
        decompressed.to_str().unwrap(),
      ])
      .output()
      .map_err(|e| format!("Failed to decompress RPX: {:?}", e))?;
    if !output.stderr.is_empty() {
      return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
  }
  Ok(())
}

fn compress(data: &[u8], output: PathBuf) -> Result<(), String> {
  let tmp_out = output.with_file_name("U-King.tmp.elf");
  write(&tmp_out, data).map_err(|e| format!("Failed to save new RPX: {}", e))?;
  let cmd_output = Command::new(&wiiurpxtool_path())
    .args(["-c", tmp_out.to_str().unwrap(), output.to_str().unwrap()])
    .output()
    .map_err(|e| format!("Failed to compress RPX: {:?}", e))?;
  if !cmd_output.stderr.is_empty() {
    return Err(String::from_utf8_lossy(&cmd_output.stderr).to_string());
  }
  Ok(())
}

#[tauri::command]
fn apply_patches(input: String, output: String, patches: Vec<Patch>) -> Result<(), String> {
  println!("{}, {}, {:?}", &input, &output, &patches);
  let input = PathBuf::from(input);
  if !input.exists() {
    return Err("Input RPX does not exist".into());
  }
  decompress(input)?;
  let mut data = read(get_decompressed_path()).map_err(|e| format!("{:?}", e))?;
  for patch in patches {
    let address = patch.addr as usize - 0x2000000 + 0x48B5E0;
    let bytes = serde_json::from_str::<Vec<u8>>(&patch.asm).unwrap();
    data.splice(address..address + 3, bytes);
  }
  compress(&data, PathBuf::from(output))?;
  Ok(())
}

#[tauri::command]
fn validate_patch(patch: String) -> Result<String, String> {
  let ks = Keystone::new(Arch::PPC, Mode::BIG_ENDIAN | Mode::MODE_32).unwrap();
  let result = ks.asm(patch, 0).map_err(|e| format!("{:?}", e))?;
  Ok(serde_json::to_string(&result.bytes).unwrap())
}

fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![validate_patch, apply_patches])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
