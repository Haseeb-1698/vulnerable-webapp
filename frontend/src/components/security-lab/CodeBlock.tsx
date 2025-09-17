import React, { useState } from 'react';

interface CodeBlockProps {
  code: string;
  language: string;
  theme: 'vulnerable' | 'secure' | 'neutral';
  showLineNumbers?: boolean;
  highlightVulnerabilities?: boolean;
  simpleDisplay?: boolean; // New prop for clean display without syntax highlighting
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language,
  theme,
  showLineNumbers = false,
  highlightVulnerabilities = false,
  simpleDisplay = false
}) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy code:', error);
    }
  };

  const getThemeClasses = () => {
    switch (theme) {
      case 'vulnerable':
        return 'bg-red-50 border-red-200';
      case 'secure':
        return 'bg-green-50 border-green-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const getHeaderClasses = () => {
    switch (theme) {
      case 'vulnerable':
        return 'bg-red-100 border-red-200 text-red-800';
      case 'secure':
        return 'bg-green-100 border-green-200 text-green-800';
      default:
        return 'bg-gray-100 border-gray-200 text-gray-800';
    }
  };

  // Simple syntax highlighting for JavaScript/TypeScript
  const highlightSyntax = (code: string) => {
    // Escape HTML first so raw angle brackets and quotes in code don't break markup
    const escapeHtml = (input: string) =>
      input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    // Work on escaped content to avoid HTML injection issues
    let highlighted = escapeHtml(code);

    // Keywords - apply first to avoid conflicts
    const keywords = [
      'const', 'let', 'var', 'function', 'async', 'await', 'return', 'if', 'else', 
      'for', 'while', 'try', 'catch', 'throw', 'new', 'class', 'extends', 'import', 
      'export', 'default', 'from', 'as', 'interface', 'type', 'enum'
    ];
    keywords.forEach(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'g');
      highlighted = highlighted.replace(regex, `<span class="text-blue-600 font-semibold">${keyword}</span>`);
    });

    // Comments - apply before strings to avoid conflicts
    highlighted = highlighted.replace(
      /\/\*[\s\S]*?\*\/|\/\/.*$/gm,
      '<span class="text-gray-500 italic">$&</span>'
    );

    // Strings - be more careful with regex to avoid conflicts
    highlighted = highlighted.replace(
      /(["'`])((?:\\.|(?!\1)[^\\])*?)\1/g,
      '<span class="text-green-600">$1$2$1</span>'
    );

    // Numbers - apply after strings to avoid conflicts with string content
    highlighted = highlighted.replace(
      /\b\d+\.?\d*\b/g,
      '<span class="text-purple-600">$&</span>'
    );

    // Vulnerability patterns (if highlighting is enabled)
    if (highlightVulnerabilities) {
      const vulnerablePatterns = [
        // SQL injection patterns
        { pattern: /\$\{[^}]*\}/g, class: 'bg-red-200 text-red-900 px-1 rounded' },
        { pattern: /dangerouslySetInnerHTML/g, class: 'bg-red-200 text-red-900 px-1 rounded' },
        { pattern: /localStorage\.setItem/g, class: 'bg-yellow-200 text-yellow-900 px-1 rounded' },
        { pattern: /weak-secret/g, class: 'bg-red-200 text-red-900 px-1 rounded' },
        { pattern: /DANGER:|VULNERABILITY:/g, class: 'bg-red-200 text-red-900 px-1 rounded font-bold' },
      ];

      vulnerablePatterns.forEach(({ pattern, class: className }) => {
        highlighted = highlighted.replace(pattern, `<span class="${className}">$&</span>`);
      });
    }

    return highlighted;
  };

  const lines = code.split('\n');
  const highlightedCode = highlightSyntax(code);
  const highlightedLines = highlightedCode.split('\n');

  return (
    <div className={`border rounded-lg overflow-hidden ${getThemeClasses()}`}>
      {/* Header */}
      <div className={`px-4 py-2 border-b flex items-center justify-between ${getHeaderClasses()}`}>
        <div className="flex items-center space-x-2">
          <span className="text-sm font-medium">
            {theme === 'vulnerable' && '⚠️ Vulnerable Code'}
            {theme === 'secure' && '✅ Secure Code'}
            {theme === 'neutral' && `${language.toUpperCase()} Code`}
          </span>
          <span className="text-xs opacity-75">
            {lines.length} lines
          </span>
        </div>
        
        <button
          onClick={copyToClipboard}
          className="text-xs px-2 py-1 rounded hover:bg-black hover:bg-opacity-10 transition-colors"
          title="Copy to clipboard"
        >
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>

      {/* Code Content */}
      <div className="relative">
        <pre className="p-4 text-sm overflow-x-auto">
          {simpleDisplay ? (
            // Simple clean display like the Hot Reload Simulation
            <code className="text-gray-800 font-mono whitespace-pre">
              {code}
            </code>
          ) : showLineNumbers ? (
            <div className="flex">
              {/* Line numbers */}
              <div className="select-none text-gray-400 text-right pr-4 border-r border-gray-300 mr-4">
                {lines.map((_, index) => (
                  <div key={index} className="leading-6">
                    {index + 1}
                  </div>
                ))}
              </div>
              
              {/* Code */}
              <div className="flex-1">
                {highlightedLines.map((line, index) => (
                  <div 
                    key={index} 
                    className="leading-6"
                    dangerouslySetInnerHTML={{ __html: line || '&nbsp;' }}
                  />
                ))}
              </div>
            </div>
          ) : (
            <code 
              className="text-gray-800"
              dangerouslySetInnerHTML={{ __html: highlightedCode }}
            />
          )}
        </pre>

        {/* Vulnerability annotations */}
        {highlightVulnerabilities && theme === 'vulnerable' && (
          <div className="absolute top-2 right-2">
            <div className="bg-red-600 text-white text-xs px-2 py-1 rounded shadow-lg">
              🚨 Security Risk
            </div>
          </div>
        )}
      </div>

      {/* Footer with security notes */}
      {theme !== 'neutral' && (
        <div className={`px-4 py-2 border-t text-xs ${getHeaderClasses()}`}>
          {theme === 'vulnerable' && (
            <div className="flex items-center space-x-2">
              <span>⚠️</span>
              <span>This code contains security vulnerabilities and should not be used in production</span>
            </div>
          )}
          {theme === 'secure' && (
            <div className="flex items-center space-x-2">
              <span>✅</span>
              <span>This code follows security best practices and is safe for production use</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};