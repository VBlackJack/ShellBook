#!/usr/bin/env python3
"""
Generate tag index page for ShellBook.
"""
import os
import re
import yaml
from pathlib import Path
from collections import defaultdict

DOCS_DIR = Path(r"G:\_dev\ShellBook\docs")
OUTPUT_FILE = DOCS_DIR / "tags-index.md"

def extract_tags_from_file(filepath):
    """Extract tags from markdown file frontmatter."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for YAML frontmatter
        if not content.startswith('---'):
            return [], None

        # Find end of frontmatter
        end = content.find('---', 3)
        if end == -1:
            return [], None

        frontmatter = content[3:end].strip()

        try:
            data = yaml.safe_load(frontmatter)
            if data and 'tags' in data:
                tags = data['tags']
                if isinstance(tags, list):
                    # Get title
                    title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
                    title = title_match.group(1) if title_match else filepath.stem
                    return tags, title
        except:
            pass

        return [], None
    except Exception as e:
        return [], None

def get_relative_path(filepath):
    """Get path relative to docs directory."""
    try:
        return filepath.relative_to(DOCS_DIR).as_posix()
    except:
        return str(filepath)

def generate_tag_index():
    """Generate the tag index page."""
    tags_dict = defaultdict(list)

    # Scan all markdown files
    print("Scanning markdown files...")
    file_count = 0

    for md_file in DOCS_DIR.rglob("*.md"):
        # Skip certain directories
        if any(skip in str(md_file) for skip in ['_guidelines', 'temp', '.git']):
            continue

        tags, title = extract_tags_from_file(md_file)
        if tags:
            rel_path = get_relative_path(md_file)
            for tag in tags:
                tag_lower = tag.lower().strip()
                if tag_lower:
                    tags_dict[tag_lower].append({
                        'title': title,
                        'path': rel_path
                    })
            file_count += 1

    print(f"Found {file_count} files with tags")
    print(f"Found {len(tags_dict)} unique tags")

    # Sort tags
    sorted_tags = sorted(tags_dict.keys())

    # Group tags by first letter
    tag_groups = defaultdict(list)
    for tag in sorted_tags:
        first_letter = tag[0].upper()
        if first_letter.isalpha():
            tag_groups[first_letter].append(tag)
        else:
            tag_groups['#'].append(tag)

    # Generate markdown content
    content = """---
tags:
  - index
  - reference
---

# Index des Tags

Cette page liste tous les tags utilisés dans ShellBook pour faciliter la navigation.

---

## Statistiques

| Métrique | Valeur |
|----------|--------|
| **Pages avec tags** | {file_count} |
| **Tags uniques** | {tag_count} |

---

## Navigation Rapide

""".format(file_count=file_count, tag_count=len(tags_dict))

    # Add quick navigation
    letters = sorted([l for l in tag_groups.keys() if l.isalpha()])
    if '#' in tag_groups:
        letters = ['#'] + letters

    content += " | ".join([f"[{l}](#{l.lower() if l != '#' else 'autres'})" for l in letters])
    content += "\n\n---\n\n"

    # Add tag sections
    for letter in letters:
        anchor = letter.lower() if letter != '#' else 'autres'
        section_name = letter if letter != '#' else 'Autres'
        content += f"## {section_name}\n\n"

        for tag in tag_groups[letter]:
            pages = tags_dict[tag]
            count = len(pages)
            content += f"### `{tag}` ({count})\n\n"

            # Sort pages by title
            pages_sorted = sorted(pages, key=lambda x: x['title'].lower())

            for page in pages_sorted[:20]:  # Limit to 20 per tag
                content += f"- [{page['title']}]({page['path']})\n"

            if len(pages) > 20:
                content += f"- *...et {len(pages) - 20} autres pages*\n"

            content += "\n"

    # Write output
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Generated: {OUTPUT_FILE}")

    # Return top tags for summary
    top_tags = sorted(tags_dict.items(), key=lambda x: -len(x[1]))[:20]
    return top_tags

if __name__ == "__main__":
    top_tags = generate_tag_index()
    print("\nTop 20 tags:")
    for tag, pages in top_tags:
        print(f"  {tag}: {len(pages)} pages")
