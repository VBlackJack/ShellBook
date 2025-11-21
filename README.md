# ShellBook

![Build Status](https://github.com/VBlackJack/ShellBook/actions/workflows/ci.yml/badge.svg)

A Documentation-as-Code knowledge base for SysOps administrators covering Linux, Windows, Kubernetes, and Security operations.

## Installation

```bash
pip install -r requirements.txt
```

## Local Development

```bash
mkdocs serve
```

Access at `http://127.0.0.1:8000`

## Build Static Site

```bash
mkdocs build
```

Output in `site/` directory.

## Deployment

Automatic deployment via GitHub Actions on push to `main` branch.

The documentation is published to GitHub Pages at:
`https://VBlackJack.github.io/ShellBook/`

## License

MIT
