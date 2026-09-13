/**
 * SummaryProvider — tree data provider for the scan summary view
 */
const vscode = require('vscode');

class SummaryProvider {
    constructor(configManager, findingsStore) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }

    refresh() {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element) {
        return element;
    }

    getChildren(element) {
        if (!element) return this._getSummaryItems();
        if (element.children) return element.children;
        return [];
    }

    _getSummaryItems() {
        const summary = this.findingsStore.getSummary();
        const items = [];

        // Header
        const headerItem = new vscode.TreeItem(
            `🛡️ Ch3ck3r — ${summary.total} total issue(s)`,
            vscode.TreeItemCollapsibleState.None
        );
        headerItem.description = this.findingsStore.getAll().length > 0
            ? 'Click to show report' : 'No issues found';
        headerItem.command = {
            command: 'ch3ck3r.showReport',
            title: 'Show Report'
        };
        items.push(headerItem);

        // Severity breakdown
        const sevItem = new vscode.TreeItem(
            'Severity Breakdown',
            vscode.TreeItemCollapsibleState.Expanded
        );
        sevItem.children = [
            this._statItem('🔴 Critical', summary.critical, '#dc3545'),
            this._statItem('🟠 High', summary.high, '#fd7e14'),
            this._statItem('🟡 Medium', summary.medium, '#ffc107'),
            this._statItem('🟢 Low', summary.low, '#28a745'),
            this._statItem('⚪ Info', summary.info, '#17a2b8'),
        ];
        items.push(sevItem);

        // OWASP categories
        if (summary.categories.length > 0) {
            const owaspItem = new vscode.TreeItem(
                'OWASP API Top 10',
                vscode.TreeItemCollapsibleState.Expanded
            );
            owaspItem.children = summary.categories.map(cat => {
                const count = this.findingsStore.getByOwaspCategory(cat).length;
                const item = new vscode.TreeItem(`  ${cat} (${count})`, vscode.TreeItemCollapsibleState.None);
                item.description = '';
                return item;
            });
            items.push(owaspItem);
        }

        // Files
        if (summary.files.length > 0) {
            const filesItem = new vscode.TreeItem(
                `Files (${summary.files.length})`,
                vscode.TreeItemCollapsibleState.Collapsed
            );
            filesItem.children = summary.files.map(f => {
                const count = this.findingsStore.getByFile(f).length;
                const item = new vscode.TreeItem(`  ${f}`, vscode.TreeItemCollapsibleState.None);
                item.description = `${count} issue(s)`;
                return item;
            });
            items.push(filesItem);
        }

        // Scan command
        const scanItem = new vscode.TreeItem('Run Scan', vscode.TreeItemCollapsibleState.None);
        scanItem.command = {
            command: 'ch3ck3r.scanFile',
            title: 'Scan File'
        };
        scanItem.iconPath = new vscode.ThemeIcon('search');
        items.push(scanItem);

        return items;
    }

    _statItem(label, count, color) {
        const item = new vscode.TreeItem(`${label}`, vscode.TreeItemCollapsibleState.None);
        item.description = `${count}`;
        if (count > 0) {
            item.iconPath = new vscode.ThemeIcon('circle-filled', new vscode.ThemeColor(color));
        }
        return item;
    }
}

module.exports = { SummaryProvider };
