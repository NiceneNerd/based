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
use wxdragon::prelude::*;

#[derive(Debug, Deserialize)]
struct Patch {
    addr: u32,
    asm: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
struct Preset {
    name: String,
    values: HashMap<String, Number>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
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

// Application state is now managed directly by individual widgets

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

fn validate_patch(addr: u64, patch: String) -> Result<String, String> {
    let result = gen_patch(addr, patch).map_err(|e| e.to_string())?;
    Ok(serde_json::to_string(&result.bytes).unwrap())
}

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
            .collect::<Vec<String>>()
            .join(&{
                i += 1;
                format!("[Preset{}]", i)
            });
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

fn show_message_dialog(parent: &Frame, title: &str, message: &str, is_error: bool) {
    let style = if is_error {
        MessageDialogStyle::OK | MessageDialogStyle::IconError
    } else {
        MessageDialogStyle::OK | MessageDialogStyle::IconInformation
    };
    
    let dialog = MessageDialog::builder(parent, message, title)
        .with_style(style)
        .build();
    dialog.show_modal();
}

fn show_preset_dialog(parent: &Frame, rules: Rules) -> Option<HashMap<String, Number>> {
    // For now, just return None to indicate no presets selected
    // TODO: Implement a proper preset selection dialog
    None
}

fn main() {
    let _ = wxdragon::main(|_| {
        let frame = Frame::builder()
            .with_title("Based: BOTW Assembly Editor")
            .with_size(Size::new(575, 500))
            .build();

        // Main sizer
        let main_sizer = BoxSizer::builder(Orientation::Vertical).build();

        // Executable group - simplified without StaticBoxSizer
        let exe_label = StaticText::builder(&frame).with_label("Executable Files").build();
        main_sizer.add(&exe_label, 0, SizerFlag::All, 10);
        
        // Input RPX
        let input_sizer = BoxSizer::builder(Orientation::Horizontal).build();
        let input_label = StaticText::builder(&frame).with_label("U-King.rpx to Patch:").build();
        let input_text = TextCtrl::builder(&frame).with_style(TextCtrlStyle::ReadOnly).build();
        let input_browse = Button::builder(&frame).with_label("Browse...").build();
        
        input_sizer.add(&input_label, 0, SizerFlag::AlignCenterVertical | SizerFlag::All, 5);
        input_sizer.add(&input_text, 1, SizerFlag::Expand | SizerFlag::All, 5);
        input_sizer.add(&input_browse, 0, SizerFlag::All, 5);
        main_sizer.add(&input_sizer, 0, SizerFlag::Expand | SizerFlag::All, 5);

        // Output RPX
        let output_sizer = BoxSizer::builder(Orientation::Horizontal).build();
        let output_label = StaticText::builder(&frame).with_label("Patched File Destination:").build();
        let output_text = TextCtrl::builder(&frame).with_style(TextCtrlStyle::ReadOnly).build();
        let output_browse = Button::builder(&frame).with_label("Browse...").build();
        
        output_sizer.add(&output_label, 0, SizerFlag::AlignCenterVertical | SizerFlag::All, 5);
        output_sizer.add(&output_text, 1, SizerFlag::Expand | SizerFlag::All, 5);
        output_sizer.add(&output_browse, 0, SizerFlag::All, 5);
        main_sizer.add(&output_sizer, 0, SizerFlag::Expand | SizerFlag::All, 5);

        // Patches group
        let patches_label = StaticText::builder(&frame).with_label("Patches").build();
        main_sizer.add(&patches_label, 0, SizerFlag::All, 10);
        
        // Patch input
        let patch_input_sizer = BoxSizer::builder(Orientation::Horizontal).build();
        let addr_label = StaticText::builder(&frame).with_label("Address:").build();
        let addr_text = TextCtrl::builder(&frame).build();
        let asm_label = StaticText::builder(&frame).with_label("Assembly:").build();
        let asm_text = TextCtrl::builder(&frame).build();
        let add_patch_btn = Button::builder(&frame).with_label("Add Patch").build();
        
        patch_input_sizer.add(&addr_label, 0, SizerFlag::AlignCenterVertical | SizerFlag::All, 5);
        patch_input_sizer.add(&addr_text, 1, SizerFlag::Expand | SizerFlag::All, 5);
        patch_input_sizer.add(&asm_label, 0, SizerFlag::AlignCenterVertical | SizerFlag::All, 5);
        patch_input_sizer.add(&asm_text, 2, SizerFlag::Expand | SizerFlag::All, 5);
        patch_input_sizer.add(&add_patch_btn, 0, SizerFlag::All, 5);
        main_sizer.add(&patch_input_sizer, 0, SizerFlag::Expand | SizerFlag::All, 5);

        // Patch list
        let patch_list = ListBox::builder(&frame).with_size(Size::new(-1, 150)).build();
        main_sizer.add(&patch_list, 1, SizerFlag::Expand | SizerFlag::All, 5);

        // Patch buttons
        let patch_btn_sizer = BoxSizer::builder(Orientation::Horizontal).build();
        let remove_btn = Button::builder(&frame).with_label("Remove").build();
        let clear_btn = Button::builder(&frame).with_label("Clear").build();
        patch_btn_sizer.add(&remove_btn, 0, SizerFlag::All, 5);
        patch_btn_sizer.add(&clear_btn, 0, SizerFlag::All, 5);
        main_sizer.add(&patch_btn_sizer, 0, SizerFlag::Left | SizerFlag::All, 5);

        // Footer buttons
        let footer_sizer = BoxSizer::builder(Orientation::Horizontal).build();
        let import_btn = Button::builder(&frame).with_label("Import Patch File").build();
        let close_btn = Button::builder(&frame).with_label("Close").build();
        let create_hax_btn = Button::builder(&frame).with_label("Create Patches.hax").build();
        let apply_btn = Button::builder(&frame).with_label("Apply Patches").build();
        
        footer_sizer.add(&import_btn, 0, SizerFlag::All, 5);
        footer_sizer.add_spacer(1);
        footer_sizer.add(&close_btn, 0, SizerFlag::All, 5);
        footer_sizer.add(&create_hax_btn, 0, SizerFlag::All, 5);
        footer_sizer.add(&apply_btn, 0, SizerFlag::All, 5);

        main_sizer.add(&footer_sizer, 0, SizerFlag::Expand | SizerFlag::All, 10);

        frame.set_sizer(main_sizer, true);

        // Create app state
        // Note: Removed unused app_state since patch list is managed directly by the ListBox

        // Event handlers
        let frame_clone = frame.clone();
        let input_text_clone = input_text.clone();
        input_browse.on_click(move |_| {
            let dialog = FileDialog::builder(&frame_clone)
                .with_message("Select U-King.rpx file")
                .with_wildcard("RPX files (*.rpx)|*.rpx")
                .with_style(FileDialogStyle::Open | FileDialogStyle::FileMustExist)
                .build();
            
            if dialog.show_modal() == ID_OK {
                if let Some(path) = dialog.get_path() {
                    input_text_clone.set_value(&path);
                }
            }
        });

        let frame_clone = frame.clone();
        let output_text_clone = output_text.clone();
        output_browse.on_click(move |_| {
            let dialog = FileDialog::builder(&frame_clone)
                .with_message("Save patched RPX file")
                .with_wildcard("RPX files (*.rpx)|*.rpx")
                .with_style(FileDialogStyle::Save | FileDialogStyle::OverwritePrompt)
                .build();
            
            if dialog.show_modal() == ID_OK {
                if let Some(path) = dialog.get_path() {
                    output_text_clone.set_value(&path);
                }
            }
        });

        let frame_clone = frame.clone();
        let addr_text_clone = addr_text.clone();
        let asm_text_clone = asm_text.clone();
        let patch_list_clone = patch_list.clone();
        add_patch_btn.on_click(move |_| {
            let addr_str = addr_text_clone.get_value();
            let asm_str = asm_text_clone.get_value();
            
            if addr_str.is_empty() || asm_str.is_empty() {
                show_message_dialog(&frame_clone, "Error", "Please enter both address and assembly", true);
                return;
            }

            // Parse address
            let addr = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
                u64::from_str_radix(&addr_str[2..], 16)
            } else {
                addr_str.parse::<u64>()
            };

            match addr {
                Ok(addr) => {
                    match validate_patch(addr, asm_str.clone()) {
                        Ok(bytes) => {
                            patch_list_clone.append(&format!("0x{:08X}: {}", addr, asm_str));
                            addr_text_clone.clear();
                            asm_text_clone.clear();
                        }
                        Err(e) => {
                            show_message_dialog(&frame_clone, "Invalid Assembly", &e, true);
                        }
                    }
                }
                Err(_) => {
                    show_message_dialog(&frame_clone, "Error", "Invalid address format", true);
                }
            }
        });

        let patch_list_clone = patch_list.clone();
        remove_btn.on_click(move |_| {
            if let Some(selection) = patch_list_clone.get_selection() {
                patch_list_clone.delete(selection);
            }
        });

        let patch_list_clone = patch_list.clone();
        clear_btn.on_click(move |_| {
            patch_list_clone.clear();
        });

        let patch_list_clone = patch_list.clone();
        import_btn.on_click(move |_| {
            let dialog = FileDialog::builder(&frame_clone)
                .with_message("Select patch file")
                .with_wildcard("Patch files (*.txt;*.hax)|*.txt;*.hax|Rules files (rules.txt)|rules.txt|HAX files (*.hax)|*.hax")
                .with_style(FileDialogStyle::Open | FileDialogStyle::FileMustExist)
                .build();
            
            if dialog.show_modal() == ID_OK {
                if let Some(path) = dialog.get_path() {
                    let path_lower = path.to_lowercase();
                    
                    if path_lower.ends_with(".hax") {
                        match parse_hax(&path) {
                            Ok(patches) => {
                                if let Some(patches_array) = patches.as_array() {
                                    for patch in patches_array {
                                        if let (Some(addr), Some(asm)) = (patch["addr"].as_u64(), patch["asm"].as_str()) {
                                            patch_list_clone.append(&format!("0x{:08X}: {}", addr, asm));
                                        }
                                    }
                                    show_message_dialog(&frame_clone, "Success", &format!("Imported {} patches", patches_array.len()), false);
                                }
                            }
                            Err(e) => {
                                show_message_dialog(&frame_clone, "Import Error", &e, true);
                            }
                        }
                    } else if path_lower.contains("rules.txt") {
                        match parse_rules(&path) {
                            Ok(rules) => {
                                if !rules.categories.is_empty() {
                                    // Show preset selection dialog
                                    if let Some(_presets) = show_preset_dialog(&frame_clone, rules.clone()) {
                                        // TODO: Apply selected presets and parse patches
                                        show_message_dialog(&frame_clone, "Info", "Preset parsing not yet implemented", false);
                                    }
                                } else {
                                    // No presets, parse patches directly
                                    match parse_patches(Path::new(&path), None) {
                                        Ok(patches) => {
                                            if let Some(patches_array) = patches.as_array() {
                                                for patch in patches_array {
                                                    if let (Some(addr), Some(asm)) = (patch["addr"].as_u64(), patch["asm"].as_str()) {
                                                        patch_list_clone.append(&format!("0x{:08X}: {}", addr, asm));
                                                    }
                                                }
                                                show_message_dialog(&frame_clone, "Success", &format!("Imported {} patches", patches_array.len()), false);
                                            }
                                        }
                                        Err(e) => {
                                            show_message_dialog(&frame_clone, "Import Error", &e, true);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                show_message_dialog(&frame_clone, "Import Error", &e, true);
                            }
                        }
                    }
                }
            }
        });

        close_btn.on_click(move |_| {
            std::process::exit(0);
        });

        let frame_clone = frame.clone();
        let patch_list_clone = patch_list.clone();
        create_hax_btn.on_click(move |_| {
            let count = patch_list_clone.get_count();
            if count == 0 {
                show_message_dialog(&frame_clone, "No Patches", "No patches to save", true);
                return;
            }

            let dialog = FileDialog::builder(&frame_clone)
                .with_message("Save patches file")
                .with_default_file("Patches.hax")
                .with_wildcard("HAX files (*.hax)|*.hax")
                .with_style(FileDialogStyle::Save | FileDialogStyle::OverwritePrompt)
                .build();
            
            if dialog.show_modal() == wxdragon_sys::WxID_OK {
                let path = dialog.get_path();
                
                // Convert patch list to patches vector
                let mut patches = Vec::new();
                for i in 0..count {
                    if let Some(item) = patch_list_clone.get_string(i) {
                        if let Some(colon_pos) = item.find(':') {
                            let addr_str = &item[..colon_pos];
                            let asm_str = &item[colon_pos + 1..].trim();
                            
                            if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                                if let Ok(bytes) = validate_patch(addr, asm_str.to_string()) {
                                    patches.push(Patch {
                                        addr: addr as u32,
                                        asm: bytes,
                                    });
                                }
                            }
                        }
                    }
                }

                match create_patches(path, patches) {
                    Ok(_) => {
                        show_message_dialog(&frame_clone, "Success", "Patches.hax created successfully", false);
                    }
                    Err(e) => {
                        show_message_dialog(&frame_clone, "Error", &e, true);
                    }
                }
            }
        });

        let frame_clone = frame.clone();
        let input_text_clone = input_text.clone();
        let output_text_clone = output_text.clone();
        let patch_list_clone = patch_list.clone();
        apply_btn.on_click(move |_| {
            let input_path = input_text_clone.get_value();
            let output_path = output_text_clone.get_value();
            let count = patch_list_clone.get_count();

            if input_path.is_empty() {
                show_message_dialog(&frame_clone, "Error", "Please select an input RPX file", true);
                return;
            }
            if output_path.is_empty() {
                show_message_dialog(&frame_clone, "Error", "Please select an output file path", true);
                return;
            }
            if count == 0 {
                show_message_dialog(&frame_clone, "Error", "No patches to apply", true);
                return;
            }

            // Convert patch list to patches vector
            let mut patches = Vec::new();
            for i in 0..count {
                if let Some(item) = patch_list_clone.get_string(i) {
                    if let Some(colon_pos) = item.find(':') {
                        let addr_str = &item[..colon_pos];
                        let asm_str = &item[colon_pos + 1..].trim();
                        
                        if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                            if let Ok(bytes) = validate_patch(addr, asm_str.to_string()) {
                                patches.push(Patch {
                                    addr: addr as u32,
                                    asm: bytes,
                                });
                            }
                        }
                    }
                }
            }

            match apply_patches(input_path, output_path, patches) {
                Ok(_) => {
                    show_message_dialog(&frame_clone, "Success", "Patches applied successfully", false);
                }
                Err(e) => {
                    show_message_dialog(&frame_clone, "Error", &e, true);
                }
            }
        });

        frame.show(true);
        frame.centre();
    });
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
