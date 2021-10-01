#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
use ini::inistr;
use keystone::{Arch, Keystone, Mode};
use serde::{Deserialize, Serialize};
use serde_json::Number;
use std::{
    collections::HashMap,
    convert::TryInto,
    fs::{read, read_to_string, write},
    path::PathBuf,
    process::Command,
};

#[derive(Debug, Deserialize)]
struct Patch {
    addr: u32,
    asm: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Preset {
    name: String,
    values: HashMap<String, Number>,
}

#[derive(Debug, Default, Serialize)]
struct Rules {
    vars: Vec<String>,
    categories: HashMap<String, Vec<Preset>>,
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

fn parse_cemu_rules(input: &PathBuf) -> Result<Rules, String> {
    let mut i = 0;
    let rules_txt: String = read_to_string(input.join("rules.txt"))
        .map_err(|e| format!("Failed to read rules.txt: {:?}", e))?
        .split("[Preset]")
        .map(|s| s.to_string())
        .intersperse_with(|| {
            i += 1;
            format!("[Preset{}]", i)
        })
        .collect();
    let rules_ref = &rules_txt;
    let ini_rules = inistr!(safe rules_ref).map_err(|_| "Failed to parse rules.txt".to_owned())?;
    let vars: Vec<String> = ini_rules
        .get("default")
        .ok_or_else(|| "No preset defaults found")?
        .keys()
        .cloned()
        .collect();
    let mut categories: HashMap<String, Vec<Preset>> = HashMap::new();
    for (_, rule) in ini_rules.iter().filter(|(k, _)| k.contains("reset")) {
        let cat = rule
            .get("category")
            .ok_or_else(|| "Preset missing category field".to_string())?
            .clone()
            .ok_or_else(|| "Preset category empty".to_string())?;
        if !categories.contains_key(&cat) {
            categories.insert(cat.clone(), vec![]);
        }
        categories.get_mut(&cat).unwrap().push(Preset {
            name: rule
                .get("name")
                .ok_or_else(|| "Preset missing name field".to_string())?
                .clone()
                .ok_or_else(|| "Preset name empty".to_string())?,
            values: rule
                .into_iter()
                .filter(|(k, _)| k.contains('$'))
                .map(|(k, v)| -> Result<(String, Number), String> {
                    let int = k.ends_with(":int");
                    let var = k.trim_end_matches(":int");
                    let v = v.clone().ok_or_else(|| "No variable value".to_string())?;
                    let value: Number =
                        serde_json::from_str(&v).or_else(|_| -> Result<Number, String> {
                            Ok(if int {
                                Number::from(
                                    meval::eval_str(&v).map_err(|_| "Invalid variable value")?
                                        as i32,
                                )
                            } else {
                                Number::from_f64(
                                    meval::eval_str(&v).map_err(|_| "Invalid variable value")?,
                                )
                                .unwrap()
                            })
                        })?;
                    Ok((var.to_owned(), value))
                })
                .collect::<Result<HashMap<String, Number>, String>>()?,
        });
    }
    Ok(Rules { vars, categories })
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
    if let Err(_) = std::fs::remove_file(&tmp_out) {
        println!("Failed to delete temp file");
    };
    Ok(())
}

#[tauri::command]
fn apply_patches(input: String, output: String, patches: Vec<Patch>) -> Result<(), String> {
    let input = PathBuf::from(input);
    if !input.exists() {
        return Err("Input RPX does not exist".into());
    }
    decompress(input)?;
    let mut data = read(get_decompressed_path()).map_err(|e| format!("{:?}", e))?;
    for patch in patches {
        let address = patch.addr as usize - 0x2000000 + 0x48B5E0;
        let bytes = serde_json::from_str::<Vec<u8>>(&patch.asm).unwrap();
        data[address] = bytes[0];
        data[address + 1] = bytes[1];
        data[address + 2] = bytes[2];
        data[address + 3] = bytes[3];
    }
    compress(&data, PathBuf::from(output))?;
    Ok(())
}

#[tauri::command]
fn validate_patch(addr: u64, patch: String) -> Result<String, String> {
    let ks = Keystone::new(Arch::PPC, Mode::BIG_ENDIAN | Mode::MODE_32).unwrap();
    let result = ks.asm(patch, addr).map_err(|e| format!("{:?}", e))?;
    Ok(serde_json::to_string(&result.bytes).unwrap())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![validate_patch, apply_patches])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_rules() {
        let patches = super::parse_cemu_rules(&std::path::PathBuf::from(
            r"E:\Cemu\graphicPacks\downloadedGraphicPacks\BreathOfTheWild\Mods\FPS++",
        ))
        .unwrap();
        println!("{}", serde_json::to_string(&patches).unwrap());
    }
}
