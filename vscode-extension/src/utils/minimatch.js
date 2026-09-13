/**
 * MiniGlob — simple glob matching for exclusion patterns
 * Supports **, *, ? patterns
 */
class MiniGlob {
    /**
     * Convert a glob pattern to a RegExp
     */
    static patternToRegex(pattern) {
        let reStr = '^';

        let i = 0;
        while (i < pattern.length) {
            const ch = pattern[i];

            if (ch === '*' && pattern[i + 1] === '*') {
                // ** — matches any number of path segments
                reStr += '.*';
                i += 2;
                // Skip trailing slash if present
                if (pattern[i] === '/') i++;
            } else if (ch === '*') {
                // * — matches anything within a single path segment
                reStr += '[^/]*';
                i++;
            } else if (ch === '?') {
                // ? — matches single char (not /)
                reStr += '[^/]';
                i++;
            } else if (ch === '.') {
                reStr += '\\.';
                i++;
            } else {
                reStr += ch;
                i++;
            }
        }

        reStr += '$';
        return new RegExp(reStr, 'i');
    }

    /**
     * Match a file path against a glob pattern
     */
    static match(filePath, pattern) {
        const regex = MiniGlob.patternToRegex(pattern);
        return regex.test(filePath);
    }
}

module.exports = { MiniGlob };
