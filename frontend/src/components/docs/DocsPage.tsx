import React, { useEffect, useMemo, useRef, useState } from 'react';
import Editor from 'rich-markdown-editor';
import { api } from '../../utils/api';

type DocNode = {
  name: string;
  path: string;
  type: 'file' | 'dir';
  children?: DocNode[];
};

function flattenTree(nodes: DocNode[]): { title: string; path: string }[] {
  const results: { title: string; path: string }[] = [];
  const visit = (n: DocNode) => {
    if (n.type === 'file' && n.name.toLowerCase().endsWith('.md')) {
      results.push({ title: n.name.replace(/\.md$/i, ''), path: n.path });
    }
    n.children?.forEach(visit);
  };
  nodes.forEach(visit);
  return results;
}

const SidebarLink: React.FC<{
  label: string;
  path: string;
  currentPath: string | null;
  onOpen: (path: string) => void;
}> = ({ label, path, currentPath, onOpen }) => (
  <button
    type="button"
    onClick={() => onOpen(path)}
    className={`block w-full text-left px-2 py-1 rounded hover:bg-gray-100 text-sm ${
      currentPath === path ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700'
    }`}
  >
    {label}
  </button>
);

const DocsPage: React.FC = () => {
  const [tree, setTree] = useState<DocNode[]>([]);
  const [currentPath, setCurrentPath] = useState<string | null>(null);
  const [markdown, setMarkdown] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [rootReadme, setRootReadme] = useState<string | null>(null);
  const [childrenFromReadme, setChildrenFromReadme] = useState<{ title: string; path: string }[]>([]);
  const rootReadmeDir = useMemo(() => (rootReadme ? rootReadme.replace(/[^/]*$/, '') : ''), [rootReadme]);
  const [headings, setHeadings] = useState<{ title: string; level: number; id: string }[]>([]);
  const [scrollTo, setScrollTo] = useState<string | undefined>(undefined);
  const editorRef = useRef<any>(null);

  function processMarkdown(raw: string): string {
    let text = raw || '';
    // Normalize line endings
    text = text.replace(/\r\n?/g, '\n');
    // Specific guard: if the starting title and early subheading (e.g., "## Overview") repeat later, cut before repetition
    try {
      const titleMatch = text.match(/^#\s+(.+)$/m);
      if (titleMatch) {
        const titleLine = titleMatch[0];
        const overviewMatch = text.match(/^##\s+Overview\b.*$/m);
        const headerAnchor = overviewMatch ? `${titleLine}\n${overviewMatch[0]}` : titleLine;
        const searchStart = Math.max(Math.floor(text.length * 0.3), text.indexOf(headerAnchor) + headerAnchor.length + 500);
        const dup = text.indexOf(headerAnchor, searchStart);
        if (dup > -1) {
          text = text.slice(0, dup).trimEnd();
        }
      }
    } catch {}
    // Robust de-duplication: search for a long prefix repeating later (common in concatenated docs)
    if (text.length > 4000) {
      const prefixLen = Math.min(4000, Math.floor(text.length / 3));
      const anchor = text.slice(0, prefixLen);
      const searchStart = Math.floor(text.length * 0.35);
      const dupAt = text.indexOf(anchor, searchStart);
      if (dupAt > -1) {
        text = text.slice(0, dupAt).trimEnd();
      } else {
        // Fallback: use first 1000 chars of content after first H1 as anchor
        const h1 = text.search(/^#\s+.+$/m);
        const start = h1 > -1 ? h1 : 0;
        const anchor2 = text.slice(start, start + 1000);
        const dupAt2 = text.indexOf(anchor2, Math.max(start + 1500, Math.floor(text.length * 0.4)));
        if (dupAt2 > -1) {
          text = text.slice(0, dupAt2).trimEnd();
        }
      }
    }
    // Ensure trailing newline for renderer
    if (!text.endsWith('\n')) text += '\n';
    return text;
  }

  useEffect(() => {
    (async () => {
      const t = await api.get<DocNode[]>('/docs/tree', { requireAuth: false });
      setTree(t);
      const allFiles = flattenTree(t);
      const readme = allFiles.find((f) => /(^|\/)readme\.md$/i.test(f.path)) || allFiles[0];
      if (readme) {
        setRootReadme(readme.path);
        // Preload README and extract chapter links so sidebar is ready immediately
        const content = await api.get<string>(`/docs/${encodeURI(readme.path)}`, { requireAuth: false });
        setMarkdown(processMarkdown(content));
        setCurrentPath(readme.path);
        // Parse Markdown links: [Title](relative.md)
        const linkRegex = /\[([^\]]+)\]\(([^)]+\.md)\)/gi;
        const links: { title: string; path: string }[] = [];
        let match;
        while ((match = linkRegex.exec(content))) {
          const label = match[1].trim();
          const rel = match[2].replace(/^\.\//, '');
          const absolute = (rootReadmeDir || readme.path.replace(/[^/]*$/, '')) + rel;
          links.push({ title: label || rel.replace(/\.md$/i, ''), path: absolute.replace(/\\/g, '/') });
        }
        setChildrenFromReadme(links);
      }
    })();
  }, []);

  const openDoc = async (path: string) => {
    setLoading(true);
    try {
      const content = await api.get<string>(`/docs/${encodeURI(path)}`, { requireAuth: false });
      setMarkdown(processMarkdown(content));
      setCurrentPath(path);
      // Do not clear chapters; keep those parsed from README
    } finally {
      setLoading(false);
    }
  };

  const filesCount = useMemo(() => flattenTree(tree).length, [tree]);

  // Update headings from editor when markdown changes
  useEffect(() => {
    const timer = setTimeout(() => {
      try {
        const list = editorRef.current?.getHeadings?.() || [];
        setHeadings(list);
      } catch {
        setHeadings([]);
      }
    }, 50);
    return () => clearTimeout(timer);
  }, [markdown]);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div className="flex gap-6">
          <aside className="w-64 shrink-0 border-r border-gray-200 pr-4 sticky top-20 max-h-[calc(100vh-5rem)] overflow-auto">
            <div className="mb-4">
              <h2 className="text-sm font-semibold text-gray-900">Documentation</h2>
              <p className="text-xs text-gray-500">{filesCount} files</p>
            </div>
            <div className="space-y-2">
              {rootReadme && (
                <div>
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Main</div>
                  <SidebarLink label="README" path={rootReadme} currentPath={currentPath} onOpen={openDoc} />
                </div>
              )}
              {childrenFromReadme.length > 0 && (
                <div className="mt-3">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Chapters</div>
                  {childrenFromReadme.map((c) => (
                    <SidebarLink key={c.path} label={c.title} path={c.path} currentPath={currentPath} onOpen={openDoc} />
                  ))}
                </div>
              )}
            </div>
          </aside>
          <main className="flex-1">
            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-0 overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-100 bg-gradient-to-r from-white to-gray-50">
                <div className="text-xs uppercase tracking-wide text-gray-400">Documentation</div>
                <div className="text-lg font-semibold text-gray-900 mt-1 break-words">
                  {currentPath ? currentPath.split('/').slice(-1)[0].replace(/\.md$/i, '') : 'Overview'}
                </div>
              </div>
              <div className="p-6">
              {loading ? (
                <div className="text-gray-500 text-sm">Loading…</div>
              ) : (
                <div className="mx-auto max-w-3xl prose prose-slate prose-headings:scroll-mt-20 leading-relaxed">
                  <Editor
                    ref={editorRef}
                    key={currentPath || 'root'}
                    value={markdown}
                    readOnly
                    scrollTo={scrollTo}
                    placeholder="Select a document"
                  />
                </div>
              )}
              </div>
            </div>
          </main>
          <aside className="w-64 shrink-0 border-l border-gray-200 pl-4 hidden lg:block sticky top-20 max-h-[calc(100vh-5rem)] overflow-auto">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-gray-900">On this page</h3>
            </div>
            <nav className="space-y-1">
              {headings.map((h) => (
                <button
                  key={h.id}
                  type="button"
                  onClick={() => setScrollTo(h.id)}
                  className={`block w-full text-left text-sm rounded px-2 py-1 hover:bg-gray-100 ${
                    h.level === 1 ? 'font-medium' : h.level === 2 ? 'ml-2' : h.level === 3 ? 'ml-4' : 'ml-6'
                  }`}
                >
                  {h.title}
                </button>
              ))}
            </nav>
          </aside>
        </div>
      </div>
    </div>
  );
};

export default DocsPage;

