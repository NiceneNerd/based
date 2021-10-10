const dialog = window.__TAURI__.dialog;
const invoke = window.__TAURI__.invoke;
const tauriWin = window.__TAURI__.window;

tauriWin.getCurrent().setIcon([]);

window.presets = {
    state: {},

    render: rules => {
        presets.state = {};
        presets.state.path = rules.path;
        let presetList = document.getElementById("preset-list");
        presetList.innerHTML = "";
        let values = {};
        for (const variable of rules.vars) {
            values[variable] = "";
        }
        presets.state.values = values;
        for (const [category, options] of Object.entries(rules.categories)) {
            presetList.innerHTML += `<div>${category}</div>`;
            presetList.innerHTML += `<select
                onchange="window.presets.update(this.value)">
                <option></option>
                ${options.map(
                    opt =>
                        `<option value='${JSON.stringify(opt.values)}''>${
                            opt.name
                        }</option>`
                )}
            </select>`;
        }
        const group = document.querySelector(".group");
        const footer = document.querySelector(".footer");
        tauriWin
            .getCurrent()
            .setSize(
                new tauriWin.PhysicalSize(256, group.offsetHeight + footer.offsetHeight)
            );
    },

    update: preset => {
        presets.state.values = { ...presets.state.values, ...JSON.parse(preset) };
        document.getElementById("submit").removeAttribute("disabled");
    },

    submit: async () => {
        try {
            const patches = await invoke("parse_patches", {
                input: presets.state.path,
                presets: presets.state.values
            });
            await invoke("update_patches", { patches });
            tauriWin.getCurrent().hide();
        } catch (error) {
            alert(error);
        }
    },

    close: () => {
        tauriWin.getCurrent().hide();
    }
};
