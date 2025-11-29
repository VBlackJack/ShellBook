#!/usr/bin/env python3
import os
import re
from pathlib import Path
from collections import defaultdict

# Configuration
project_root = os.getcwd()
md_files = {}
broken_links = []
missing_anchors = []

print("[1] Collecting markdown files...")
for md_file in Path("docs").rglob("*.md"):
    rel_path = str(md_file.relative_to("docs")).replace("\\", "/")
    md_files[rel_path] = str(md_file)

print(f"Found {len(md_files)} markdown files\n")

# Pattern pour trouver les liens markdown
link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
anchor_pattern = re.compile(r'^#{1,6}\s+(.+)$', re.MULTILINE)

print("[2] Analyzing links...")
for rel_path, abs_path in sorted(md_files.items()):
    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Extract anchors
    anchors = {}
    for match in anchor_pattern.finditer(content):
        title = match.group(1).strip()
        anchor_id = re.sub(r'[^\w\s-]', '', title).lower()
        anchor_id = re.sub(r'\s+', '-', anchor_id).strip('-')
        anchors[anchor_id] = title
    
    md_files[rel_path] = {'path': abs_path, 'anchors': anchors}
    
    # Parse links
    for match in link_pattern.finditer(content):
        text = match.group(1)
        link = match.group(2)
        line_num = content[:match.start()].count('\n') + 1
        
        # Skip external links
        if link.startswith(('http://', 'https://')):
            continue
        
        # Skip pseudo-links
        if link.startswith(('$', 'Get-Content', '[')) or 'WorkingSet64' in link:
            continue
        
        # Internal anchor only
        if link.startswith('#'):
            anchor = link[1:]
            if anchor and anchor not in anchors:
                missing_anchors.append({
                    'file': rel_path,
                    'line': line_num,
                    'anchor': anchor,
                    'text': text
                })
        else:
            # File link
            target_path = link.split('#')[0]
            target_anchor = link.split('#')[1] if '#' in link else None
            
            if target_path:
                # Handle trailing slash
                if target_path.endswith('/'):
                    check_path = target_path.rstrip('/') + '/index.md'
                else:
                    check_path = target_path
                
                # Resolve relative path
                current_dir = str(Path(rel_path).parent)
                if current_dir == '.':
                    resolved_path = check_path
                else:
                    resolved_path = str(Path(current_dir) / check_path).replace('\', '/')
                
                # Normalize path (handle .. and .)
                parts = []
                for part in resolved_path.split('/'):
                    if part == '..' and parts:
                        parts.pop()
                    elif part not in ('.', ''):
                        parts.append(part)
                resolved_path = '/'.join(parts)
                
                # Check if file exists
                if resolved_path not in md_files:
                    broken_links.append({
                        'file': rel_path,
                        'line': line_num,
                        'target': target_path,
                        'resolved': resolved_path,
                        'text': text
                    })
                elif target_anchor:
                    # Check anchor exists
                    target_anchors = md_files[resolved_path].get('anchors', {})
                    if target_anchor not in target_anchors:
                        missing_anchors.append({
                            'file': rel_path,
                            'line': line_num,
                            'target': f"{resolved_path}#{target_anchor}",
                            'text': text
                        })

print(f"Analysis complete!\n")

# Print results
print("=" * 100)
print("AUDIT REPORT: Internal Links - ShellBook")
print("=" * 100)

print(f"\nMarkdown files scanned: {len(md_files)}")

if broken_links:
    print(f"\n[BROKEN FILES] {len(broken_links)} links to non-existent files\n")
    for i, link in enumerate(broken_links, 1):
        print(f"{i}. Source: docs/{link['file']} (line {link['line']})")
        print(f"   Link target: {link['target']}")
        print(f"   Resolved to: docs/{link['resolved']}")
        print(f"   Link text: [{link['text']}]")
        print()
else:
    print("\n✓ All file links are valid!\n")

if missing_anchors:
    print(f"\n[MISSING ANCHORS] {len(missing_anchors)} missing anchors\n")
    for i, anchor in enumerate(missing_anchors, 1):
        print(f"{i}. Source: docs/{anchor['file']} (line {anchor['line']})")
        if 'target' in anchor:
            print(f"   Target: {anchor['target']}")
        else:
            print(f"   Missing anchor: #{anchor['anchor']}")
        print(f"   Link text: [{anchor['text']}]")
        print()
else:
    print("\n✓ All anchors exist!\n")

print("=" * 100)
print(f"Summary: {len(broken_links)} broken files, {len(missing_anchors)} missing anchors")
print("=" * 100)
