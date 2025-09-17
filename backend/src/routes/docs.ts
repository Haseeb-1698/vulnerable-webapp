import express from 'express';
import path from 'path';
import fs from 'fs';

const router = express.Router();

const DOCS_ROOT = path.join(__dirname, '../../..', 'docs');

type DocNode = {
  name: string;
  path: string; // relative path from docs root
  type: 'file' | 'dir';
  children?: DocNode[];
};

function buildTree(dir: string, base = ''): DocNode[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  // sort directories first, then files alphabetically
  const sorted = entries.sort((a, b) => {
    if (a.isDirectory() && !b.isDirectory()) return -1;
    if (!a.isDirectory() && b.isDirectory()) return 1;
    return a.name.localeCompare(b.name);
  });

  return sorted.map((entry) => {
    const abs = path.join(dir, entry.name);
    const rel = path.posix.join(base.replace(/\\/g, '/'), entry.name);
    if (entry.isDirectory()) {
      return {
        name: entry.name,
        path: rel,
        type: 'dir',
        children: buildTree(abs, rel),
      } as DocNode;
    }
    return {
      name: entry.name,
      path: rel,
      type: 'file',
    } as DocNode;
  });
}

router.get('/tree', (_req, res) => {
  try {
    if (!fs.existsSync(DOCS_ROOT)) {
      return res.json([]);
    }
    const tree = buildTree(DOCS_ROOT);
    res.json(tree);
  } catch (err) {
    res.status(500).json({ error: 'Failed to build docs tree' });
  }
});

router.get('/*', (req, res) => {
  try {
    const rel = req.params[0] || '';
    // prevent path traversal
    const safeRel = rel.replace(/\\/g, '/');
    const abs = path.join(DOCS_ROOT, safeRel);
    if (!abs.startsWith(DOCS_ROOT)) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    if (!fs.existsSync(abs)) {
      return res.status(404).json({ error: 'Not found' });
    }
    const stat = fs.statSync(abs);
    if (stat.isDirectory()) {
      // default to README.md inside directory if present
      const readme = ['README.md', 'readme.md'].map((f) => path.join(abs, f)).find(fs.existsSync);
      if (readme) {
        return res.type('text/markdown').send(fs.readFileSync(readme, 'utf8'));
      }
      return res.status(400).json({ error: 'Path is a directory' });
    }
    const data = fs.readFileSync(abs, 'utf8');
    res.type('text/markdown').send(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read document' });
  }
});

export default router;

