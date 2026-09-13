/**
 * FindingsProvider — tree data provider for the findings view
 */
const vscode = require('vscode');

class FindingsProvider {
    constructor(configManager, findingsStore, context) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this.context = context;
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
        if (!element) {
            return this._getRootItems();
        }
        if (element.children) {
            return element.children;
        }
        return [];
    }

    _getRootItems() {
        const items = [];

        // Severity groups with counts
        const groups = [
            { label: 'Critical', severity: 'critical', icon: '$(error)', color: '#dc3545' },
            { label: 'High', severity: 'high', icon: '$(warning)', color: '#fd7e14' },
            { label: 'Medium', severity: 'medium', icon: '$(info)', color: '#ffc107' },
            { label: 'Low', severity: 'low', icon: '$(chevron-down)', color: '#28a745' },
            { label: 'Info', severity: 'info', icon: '$(bell)', color: '#17a2b8' },
        ];

        for (const group of groups) {
            const findings = this.findingsStore.getBySeverity(group.severity);
            if (findings.length === 0) continue;

            const groupItem = new vscode.TreeItem(
                `${group.icon} ${group.label} (${findings.length})`,
                vscode.TreeItemCollapsibleState.Collapsed
            );
            groupItem.contextValue = 'severityGroup';
            groupItem.description = '';

            const owaspGroups = {};
            for (const f of findings) {
                const key = f.owasp_category || 'Uncategorized';
                if (!owaspGroups[key]) owaspGroups[key] = [];
                owaspGroups[key].push(f);
            }

            const children = [];
            for (const [owaspCat, catFindings] of Object.entries(owaspGroups)) {
                const catItem = new vscode.TreeItem(
                    `${owaspCat} (${catFindings.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed
                );
                catItem.contextValue = 'owaspCategory';
                catItem.description = '';

                const findingItems = catFindings.map(f => {
                    const isFP = this.findingsStore.falsePositives.has(f.id);
                    const label = `${f.title}${isFP ? ' [FP]' : ''}`;
                    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
                    item.contextValue = isFP ? 'findingFalsePositive' : 'finding';
                    item.description = f.file ? `${f.file.split('/').pop()}:${f.line || 1}` : '';
                    item.tooltip = `${f.title}\n${f.description}\n${f.remediation ? `\nFix: ${f.remediation}` : ''}`;
                    item.command = {
                        command: 'ch3ck3r.openFinding',
                        title: 'Open Finding',
                        arguments: [f]
                    };
                    item.iconPath = this._getSeverityIcon(f.severity);
                    item.finding = f;
                    return item;
                });

                catItem.children = findingItems;
                children.push(catItem);
            }

            groupItem.children = children;
            items.push(groupItem);
        }

        if (items.length === 0) {
            const emptyItem = new vscode.TreeItem('No findings — scan a file to start');
            emptyItem.contextValue = 'empty';
            return [emptyItem];
        }

        return items;
    }

    _getSeverityIcon(severity) {
        const icons = {
            critical: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
            high: new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground')),
            medium: new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground')),
            low: new vscode.ThemeIcon('check', new vscode.ThemeColor('gitDecoration.addedResourceForeground')),
            info: new vscode.ThemeIcon('bell'),
        };
        return icons[severity] || new vscode.ThemeIcon('question');
    }
}

module.exports = { FindingsProvider };
