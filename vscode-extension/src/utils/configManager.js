/**
 * ConfigManager — typed access to VS Code settings
 */
const vscode = require('vscode');

class ConfigManager {
    constructor() {
        this.section = 'ch3ck3r';
    }

    get(key, defaultValue) {
        const config = vscode.workspace.getConfiguration(this.section);
        return config.get(key, defaultValue);
    }

    update(key, value, target) {
        const config = vscode.workspace.getConfiguration(this.section);
        return config.update(key, value, target || vscode.ConfigurationTarget.Global);
    }

    get severityThreshold() {
        return this.get('severityThreshold', 'medium');
    }

    get enabled() {
        return this.get('enabled', true);
    }
}

module.exports = { ConfigManager };
