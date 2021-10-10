#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
use anyhow::{anyhow, format_err, Context, Result};
use binread::{BinRead, BinReaderExt};
use ini::inistr;
use keystone::{Arch, Keystone, Mode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};
use std::{
    collections::HashMap,
    fs::{read, read_to_string, write},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tauri::{Manager, WindowEvent};

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

#[derive(Debug, Default, Deserialize, Serialize)]
struct Rules {
    path: String,
    vars: Vec<String>,
    categories: HashMap<String, Vec<Preset>>,
}

#[derive(Debug, BinRead)]
#[br(assert(_size == 4))]
struct HaxPatch {
    _size: u16,
    addr: u32,
    bytes: [u8; 4],
}

#[derive(Debug, BinRead)]
struct HaxFile {
    _count: u16,
    #[br(count = _count)]
    patches: Vec<HaxPatch>,
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

fn decompress(input: PathBuf) -> Result<()> {
    let decompressed = get_decompressed_path();
    if !decompressed.exists() {
        let output = Command::new(&wiiurpxtool_path())
            .args([
                "-d",
                input.to_str().unwrap(),
                decompressed.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| format_err!("Failed to decompress RPX: {:?}", e))?;
        if !output.stderr.is_empty() {
            return Err(format_err!("{}", String::from_utf8_lossy(&output.stderr)));
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
fn create_patches(output: String, patches: Vec<Patch>) -> Result<(), String> {
    let write_patches = || -> Result<()> {
        let mut writer = BufWriter::new(std::fs::File::create(&output)?);
        writer.write(&(patches.len() as u16).to_be_bytes())?;
        for patch in patches {
            writer.write(&4u16.to_be_bytes())?;
            writer.write(&(patch.addr + 0xA900000).to_be_bytes())?;
            writer.write(&serde_json::from_str::<Vec<u8>>(&patch.asm).unwrap())?;
        }
        Ok(())
    };
    write_patches().map_err(|e| e.to_string())
}

#[tauri::command]
fn apply_patches(input: String, output: String, patches: Vec<Patch>) -> Result<(), String> {
    let input = PathBuf::from(input);
    if !input.exists() {
        return Err("Input RPX does not exist".into());
    }
    decompress(input).map_err(|e| e.to_string())?;
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

fn gen_patch(addr: u64, patch: String) -> Result<keystone::AsmResult> {
    let re = regex::Regex::new(r"[rf](\d{1,2})")?;
    let patch = re.replace_all(&patch, "$1").to_string();
    let ks = Keystone::new(Arch::PPC, Mode::BIG_ENDIAN | Mode::MODE_32).unwrap();
    Ok(ks.asm(patch, addr).map_err(|e| format_err!("{:?}", e))?)
}

#[tauri::command]
fn validate_patch(addr: u64, patch: String) -> Result<String, String> {
    let result = gen_patch(addr, patch).map_err(|e| e.to_string())?;
    Ok(serde_json::to_string(&result.bytes).unwrap())
}

#[tauri::command]
fn open_presets(window: tauri::Window, presets: Rules) {
    let window = window.get_window("presets").unwrap();
    window.show().unwrap();
    window
        .eval(&format!(
            "window.presets.render(JSON.parse(`{}`));",
            &serde_json::to_string(&presets).unwrap()
        ))
        .unwrap();
}

#[tauri::command]
fn parse_rules(input: &str) -> Result<Rules, String> {
    fn parse_value((k, v): (&String, &Option<String>)) -> Result<(String, Number)> {
        let int = k.ends_with(":int");
        let v = v.clone().context("No variable value")?;
        let value: Number = match serde_json::from_str(&v) {
            Ok(v) => v,
            Err(_) => {
                if int {
                    Number::from(meval::eval_str(&v).context("Invalid variable value")? as i32)
                } else {
                    Number::from_f64(meval::eval_str(&v).context("Invalid variable value")?)
                        .unwrap()
                }
            }
        };
        Ok((k.to_owned(), value))
    }
    let parse = || -> Result<Rules> {
        let mut i = 0;
        let rules_txt: String = read_to_string(input)?
            .split("[Preset]")
            .map(|s| s.to_string())
            .intersperse_with(|| {
                i += 1;
                format!("[Preset{}]", i)
            })
            .collect();
        if !rules_txt.contains("[Preset") {
            return Ok(Rules {
                path: input.to_owned().replace("\\", "/"),
                ..Default::default()
            });
        }
        let rules_ref = &rules_txt;
        let ini_rules = inistr!(safe rules_ref).map_err(|_| anyhow!("Invalid rules.txt"))?;
        let vars: Vec<String> = ini_rules
            .get("default")
            .context("No preset defaults found")?
            .keys()
            .cloned()
            .collect();
        let mut categories: HashMap<String, Vec<Preset>> = HashMap::new();
        for (_, rule) in ini_rules.iter().filter(|(k, _)| k.contains("reset")) {
            let cat = rule
                .get("category")
                .context("Preset missing category field")?
                .clone()
                .context("Preset category empty")?;
            if !categories.contains_key(&cat) {
                categories.insert(cat.clone(), vec![]);
            }
            categories.get_mut(&cat).unwrap().push(Preset {
                name: rule
                    .get("name")
                    .context("Preset missing name field")?
                    .clone()
                    .context("Preset name empty")?,
                values: {
                    if let Some(_) = rule.get("default") {
                        ini_rules
                            .get("default")
                            .unwrap()
                            .iter()
                            .map(parse_value)
                            .collect::<Result<HashMap<String, Number>>>()?
                    } else {
                        rule.iter()
                            .filter(|(k, _)| k.contains('$'))
                            .map(parse_value)
                            .collect::<Result<HashMap<String, Number>>>()?
                    }
                },
            });
        }
        Ok(Rules {
            path: input.to_owned().replace("\\", "/"),
            vars,
            categories,
        })
    };
    parse().map_err(|e| e.to_string())
}

#[tauri::command]
fn parse_patches(input: &Path, presets: Option<Value>) -> Result<Value, String> {
    let parse = || -> Result<Value> {
        let patch_file = std::fs::read_dir(input.parent().unwrap())?
            .filter_map(|f| f.ok())
            .find(|f| f.file_name().to_str().unwrap().starts_with("patch"))
            .context("No patch file found")?
            .path();
        let mut patch_txt = std::fs::read_to_string(&patch_file)?;
        if patch_txt.contains("codecave") || patch_txt.contains("codeCave") {
            return Err(anyhow!("Code cave patches are not supported"));
        }
        if let Some(presets) = presets {
            for (k, v) in presets.as_object().unwrap() {
                let k = k.trim_end_matches(":int");
                patch_txt = patch_txt.replace(k, &serde_json::to_string(&v)?);
            }
        }
        let re = regex::Regex::new(r"(0x[0-9a-fA-F]+) *= *(.+):\r*\n").unwrap();
        re.captures_iter(&patch_txt.clone()).for_each(|c| {
            patch_txt = patch_txt.replace(c.get(0).unwrap().as_str(), "");
            patch_txt = patch_txt.replace(c.get(2).unwrap().as_str(), c.get(1).unwrap().as_str());
        });
        let patch_ref = &patch_txt;
        let patch_config = inistr!(safe patch_ref).map_err(|e| format_err!("{}", e))?;
        let patch_section = patch_config
            .iter()
            .map(|(_, v)| v)
            .find(|v| {
                v.contains_key("modulematches")
                    && v.get("modulematches").as_ref().unwrap().as_ref().unwrap() == "0x6267BFD0"
            })
            .context("Missing module matches")?;
        Ok(Value::Array(
            patch_section
                .iter()
                .filter(|(k, _)| k.starts_with("0x"))
                .filter_map(|(addr, instr)| -> Option<Result<Value>> {
                    if let Some(instr) = instr {
                        let try_build_patch = || -> Result<Value> {
                            let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
                                .with_context(|| format_err!("Bad address {}", addr))?;
                            Ok(json!({
                                "addr": addr,
                                "asm": serde_json::to_string(&gen_patch(addr, instr.clone())?.bytes).unwrap()
                            }))
                        };
                        Some(try_build_patch())
                    } else {
                        None
                    }
                })
                .collect::<Result<Vec<Value>>>()?,
        ))
    };
    parse().map_err(|e| e.to_string())
}

#[tauri::command]
fn parse_hax(input: &str) -> Result<Value, String> {
    let parse = || -> Result<Value> {
        let mut data = std::io::Cursor::new(std::fs::read(input)?);
        let hax: HaxFile = data.read_be()?;
        Ok(Value::Array(
            hax.patches
                .iter()
                .map(|p| {
                    Ok(json!({
                        "addr": p.addr - 0xA900000,
                        "asm": serde_json::to_string(&p.bytes)?
                    }))
                })
                .collect::<Result<Vec<Value>>>()?,
        ))
    };
    parse().map_err(|e| e.to_string())
}

#[tauri::command]
fn update_patches(window: tauri::Window, patches: Value) -> Result<(), String> {
    window
        .get_window("main")
        .unwrap()
        .eval(&format!(
            "window.based.updatePatches(`{}`)",
            &serde_json::to_string(&patches).unwrap()
        ))
        .unwrap();
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let main_window = app.get_window("main").unwrap();
            main_window.on_window_event(|e| {
                if let WindowEvent::Destroyed = e {
                    std::process::exit(0);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            validate_patch,
            apply_patches,
            create_patches,
            parse_rules,
            open_presets,
            parse_patches,
            parse_hax,
            update_patches
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_rules() {
        let patches = super::parse_rules(
            r"E:\Cemu\graphicPacks\downloadedGraphicPacks\BreathOfTheWild\Mods\FPS++",
        )
        .unwrap();
        println!("{}", serde_json::to_string(&patches).unwrap());
    }
}
