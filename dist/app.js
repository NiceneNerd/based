const dialog = window.__TAURI__.dialog;
// const invoke = window.__TAURI__.invoke;
const invoke = async () => "testing";

let module = {    
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
        document.querySelector('[name="patches"]').innerHTML = state.patches
            .map(
                p =>
                    `<option value='${JSON.stringify(p)}'>` +
                    `0x${p.addr.toString(16)} = ${p.asm}</option>`
            )
            .join("\n");
    },
    
    addPatch: async () => {
        const addrText = document.querySelector('[name="addr"]').value;
        const addr = parseInt(addrText, 16);
        if (addr === NaN || !addrText.startsWith("0x") || addrText.length !== 10) {
            alert("Invalid address: " + addrText);
            return;
        }
        const asmText = document.querySelector('[name="addr"]').value;
        try {
            const asm = await invoke(asmText);
            state.patches.push({ addr, asm });
        } catch (error) {
            alert("Invalid assembly: " + asmText + ".\n\n");
            return;
        }
        renderPatches();
    },
    
    removePatch: () => {
        const patch = JSON.parse(document.querySelector('[name="patches"]').value);
        state.patches = state.patches.filter(p => p != patch);
        renderPatches();
    },
    
    state: {
        inputRpx: "",
        outputRpx: "",
        address: 0,
        asm: "",
        patches: []
    }   
}

window.based = module;
