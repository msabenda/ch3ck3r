/**
 * StatusBarManager — manages the Ch3ck3r status bar indicator
 */
const vscode = require('vscode');

class StatusBarManager {
    constructor() {
        this.item = null;
    }

    create(context) {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
        this.item.command = 'ch3ck3r.showReport';
        this.item.tooltip = 'Ch3ck3r API Security — Click to view report';
        this.item.show();
        context.subscriptions.push(this.item);
    }

    setIdle() {
        if (!this.item) return;
        this.item.text = '$(shield) Ch3ck3r';
        this.item.backgroundColor = undefined;
        this.item.color = undefined;
    }

    setSecure() {
        if (!this.item) return;
        this.item.text = '$(shield) Ch3ck3r ✓';
        this.item.backgroundColor = undefined;
        this.item.color = '#28a745';
    }

    setScanning(message) {
        if (!this.item) return;
        this.item.text = `$(sync~spin) Ch3ck3r: ${message}`;
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        this.item.color = undefined;
    }

    setHasIssues(count) {
        if (!this.item) return;
        const color = count > 0 ? '#dc3545' : '#ffc107';
        this.item.text = `$(shield) Ch3ck3r: ${count} issue${count !== 1 ? 's' : ''}`;
        this.item.backgroundColor = count > 0 ? new vscode.ThemeColor('statusBarItem.errorBackground') : undefined;
        this.item.color = color;
    }

    setConnected(url) {
        if (!this.item) return;
        this.item.text = `$(plug) Ch3ck3r: Connected`;
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
        this.item.color = '#00d4aa';
        this.item.tooltip = `Connected to ${url}`;
    }

    setError(message) {
        if (!this.item) return;
        this.item.text = `$(alert) Ch3ck3r: Error`;
        this.item.tooltip = message;
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        this.item.color = '#dc3545';
    }

    updateText() {
        // Called when settings change
        const config = vscode.workspace.getConfiguration('ch3ck3r');
        if (!config.get('showStatusBar', true)) {
            this.item.hide();
        } else {
            this.item.show();
        }
    }

    dispose() {
        if (this.item) {
            this.item.dispose();
            this.item = null;
        }
    }
}

module.exports = { StatusBarManager };
