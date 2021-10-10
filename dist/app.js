const dialog = window.__TAURI__.dialog;
const invoke = window.__TAURI__.invoke;
const tauriWin = window.__TAURI__.window;

let state = {
    inputRpx: "",
    outputRpx: "",
    address: 0,
    asm: "",
    patches: []
};

window.based = {
    openFile: async () => {
        const file = await dialog.open();
        if (file) {
            document.querySelector('[name="input-rpx"]').value = file;
            state.inputRpx = file;
        }
    },

    saveFile: async () => {
        const file = await dialog.save();
        if (file) {
            document.querySelector('[name="output-rpx"]').value = file;
            state.outputRpx = file;
        }
    },

    renderPatches: () => {
        document.querySelector('[name="patches"]').innerHTML =
            state.patches.length > 0
                ? state.patches
                      .map(
                          p =>
                              `<option value='${JSON.stringify(p)}'>` +
                              `0x${p.addr.toString(16)} = ${p.asm}</option>`
                      )
                      .join("\n")
                : '<option value="">No patches</option>';
    },

    addPatch: async () => {
        const addrText = document.querySelector('[name="addr"]').value;
        const addr = parseInt(addrText, 16);
        if (addr === NaN || !addrText.startsWith("0x") || addrText.length !== 10) {
            alert("Invalid address: " + addrText);
            return;
        }
        const asmText = document.querySelector('[name="asm"]').value;
        try {
            const asm = await invoke("validate_patch", {
                addr,
                patch: asmText
            });
            state.patches.push({ addr, asm });
        } catch (error) {
            alert("Invalid assembly: " + asmText + ".\n\n" + error);
            return;
        }
        based.renderPatches();
    },

    removePatch: () => {
        const patches = document.querySelector('[name="patches"]');
        const patch = JSON.parse(patches.options[patches.selectedIndex].value);
        state.patches = state.patches.filter(p => p.addr != patch.addr);
        based.renderPatches();
    },

    clearPatches: () => {
        state.patches = [];
        based.renderPatches();
    },

    applyPatches: async () => {
        try {
            await invoke("apply_patches", {
                input: state.inputRpx,
                output: state.outputRpx,
                patches: state.patches
            });
        } catch (error) {
            alert(error);
            return;
        }
        alert("Patch complete!");
    },

    createPatchesFile: async () => {
        try {
            const file = await dialog.save({
                defaultPath: "Patches.hax",
                filters: [
                    {
                        name: "CafeLoader patches file",
                        extensions: ["hax"]
                    }
                ]
            });
            if (!file) return;
            await invoke("create_patches", {
                output: file,
                patches: state.patches
            });
        } catch (error) {
            alert(error);
            return;
        }
        alert("Patch file created!");
    },

    importPatch: async () => {
        const file = await dialog.open({
            filters: [
                {
                    name: "Cemu rules.txt",
                    extensions: ["txt"]
                },
                {
                    name: "CafeLoader Patches.hax",
                    extensions: ["hax"]
                }
            ]
        });
        if (!file) return;
        if (file.endsWith("txt")) {
            const presets = await invoke("parse_rules", {
                input: file
            });
            if (presets.vars.length > 0) await invoke("open_presets", { presets });
            else {
                const patches = await invoke("parse_patches", { input: file });
                based.updatePatches(JSON.stringify(patches));
            }
        } else if (file.endsWith("hax")) {
            const patches = await invoke("parse_hax", { input: file });
            based.updatePatches(JSON.stringify(patches));
        }
    },

    updatePatches: patches => {
        state.patches.push(...JSON.parse(patches));
        based.renderPatches();
    },

    close: async () => {
        window.__TAURI__.process.exit(0);
    }
};

window.addEventListener("beforeunload", () => {
    console.log("Exiting");
    window.based.close();
});
