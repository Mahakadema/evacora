
const versionSelector = document.getElementById("version-selector");

function generateElement(current) {
    const versions = [
        ["v2", "2.0.0"],
        ["v1", "1.2.2"]
    ];
    return '<select onchange="window.location.href = `../${this.options[this.selectedIndex].value}`">' +
        versions.map(v => current === v[0] ? `<option value="${v[0]}" selected>${v[1]}</option>` : `<option value="${v[0]}">${v[1]}</option>`) +
        "</select>";
}

versionSelector.innerHTML = generateElement(window.location.pathname.split("/").reverse().find(v => v));
