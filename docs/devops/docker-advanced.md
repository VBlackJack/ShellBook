# Docker Pro Tips & Hacks

`#docker` `#productivity` `#security`

Advanced Docker features that will save you hours of work.

---

## Tip 1: Instant Scaffolding (`docker init`)

Stop writing Dockerfiles from scratch. Let Docker generate them for you.

```bash
cd my-project
docker init
```

**What it does:**

- Detects your project language (Python, Node, Go, Rust, etc.)
- Generates optimized `Dockerfile` with best practices
- Creates `compose.yaml` for local development
- Adds `.dockerignore` file

**Example output:**

```
? What application platform does your project use? Python
? What version of Python? 3.11
? What port does your server listen on? 8000

✔ Created Dockerfile
✔ Created compose.yaml
✔ Created .dockerignore
```

!!! tip "Works with existing projects"
    Run `docker init` in any existing project directory. It analyzes your code and generates appropriate configs.

---

## Tip 2: Hot Reloading (`docker compose watch`)

Replace complex volume mounts with native file sync for development.

```bash
docker compose watch
```

**compose.yaml configuration:**

```yaml
services:
  web:
    build: .
    ports:
      - "3000:3000"
    develop:
      watch:
        # Sync files without rebuild
        - action: sync
          path: ./src
          target: /app/src

        # Sync and restart container
        - action: sync+restart
          path: ./config
          target: /app/config

        # Rebuild on dependency changes
        - action: rebuild
          path: ./package.json
```

**Actions explained:**

| Action | Behavior |
|--------|----------|
| `sync` | Copy files to container (hot reload) |
| `sync+restart` | Copy files and restart container |
| `rebuild` | Trigger full image rebuild |

!!! warning "Replaces bind mounts"
    `docker compose watch` is cleaner than volume mounts for development:

    - No permission issues
    - Better performance on macOS/Windows
    - Selective sync (ignore node_modules)

---

## Tip 3: Debugging Distroless (`docker debug`)

**Problem:** Your production container has no shell, no bash, no tools. How do you debug?

```bash
# This fails on distroless/minimal images
docker exec -it my-container /bin/sh
# Error: executable file not found
```

**Solution:** Docker Debug attaches a debugging toolkit.

```bash
docker debug <container_id>
```

**What you get:**

- Full shell access (even on distroless)
- vim, curl, wget, netcat pre-installed
- Process inspection tools
- Network debugging utilities

```bash
# Debug a running container
docker debug my-api-container

# Debug with a specific image as toolkit
docker debug --shell bash my-container

# Debug a stopped container
docker debug --platform linux/amd64 my-container
```

!!! info "How it works"
    Docker Debug creates a sidecar container that shares the target container's namespaces (PID, network, filesystem) without modifying the original image.

---

## Tip 4: Security Scanning (`docker scout`)

Built-in CVE scanning and remediation recommendations.

### Quick Vulnerability Overview

```bash
# Scan current directory's image
docker scout quickview

# Scan specific image
docker scout quickview nginx:latest

# Output example:
#   Target     │ nginx:latest
#   Digest     │ sha256:abc123...
#   Base Image │ debian:bookworm-slim
#
#   Vulnerabilities
#     Critical: 2
#     High:     5
#     Medium:   12
```

### Get Fix Recommendations

```bash
# Get upgrade recommendations
docker scout recommendations nginx:latest

# Output example:
#   Recommended fixes:
#   ✓ Update base image from debian:bookworm-slim to debian:bookworm-slim@sha256:...
#     Fixes: CVE-2024-1234 (Critical), CVE-2024-5678 (High)
```

### Compare Images

```bash
# Compare two image versions
docker scout compare nginx:1.24 nginx:1.25

# See what changed (new CVEs, fixed CVEs)
```

!!! danger "CI/CD Integration"
    Add Scout to your pipeline to fail builds on critical CVEs:

    ```yaml
    - name: Scan for vulnerabilities
      run: |
        docker scout cves --exit-code --only-severity critical,high
    ```

---

## Tip 5: GUI Apps in Containers (X11 Forwarding)

Run graphical applications (browsers, IDEs, games) inside containers.

### Linux Setup

```bash
# Allow X11 connections
xhost +local:docker

# Run Firefox in container
docker run -it --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --network host \
  jess/firefox
```

### macOS Setup (XQuartz)

```bash
# 1. Install XQuartz
brew install --cask xquartz

# 2. Enable network connections in XQuartz preferences
# XQuartz → Preferences → Security → "Allow connections from network clients"

# 3. Restart and allow connections
xhost +localhost

# 4. Run with DISPLAY pointing to host
docker run -it --rm \
  -e DISPLAY=host.docker.internal:0 \
  jess/firefox
```

### Windows Setup (VcXsrv)

```powershell
# 1. Install VcXsrv
# 2. Run XLaunch with "Disable access control" checked

# 3. Run container
docker run -it --rm `
  -e DISPLAY=host.docker.internal:0 `
  jess/firefox
```

!!! tip "Popular GUI Containers"
    - `jess/firefox` - Firefox browser
    - `linuxserver/firefox` - Firefox with VNC
    - `linuxserver/chromium` - Chromium browser
    - `kasmweb/*` - Browser isolation (enterprise)

---

## Tip 6: Multi-Arch Speed (`docker build --builder cloud`)

**Problem:** Building x86/amd64 images on Apple Silicon (ARM) is painfully slow due to QEMU emulation.

```bash
# This is SLOW on M1/M2 Mac (emulation)
docker build --platform linux/amd64 -t myapp .
```

**Solution:** Offload builds to Docker Build Cloud.

```bash
# Create cloud builder
docker buildx create --driver cloud myorg/mybuilder

# Build using cloud (native speed for all architectures)
docker build --builder cloud-myorg-mybuilder \
  --platform linux/amd64,linux/arm64 \
  -t myapp:latest .
```

### Benefits

| Local Build (Emulated) | Cloud Build (Native) |
|------------------------|----------------------|
| 10-20 minutes | 1-2 minutes |
| CPU at 100% | Local CPU idle |
| Single arch at a time | Multi-arch parallel |

### Setup

```bash
# Login to Docker Hub
docker login

# Create cloud builder (requires Docker subscription)
docker buildx create --driver cloud <org>/<builder-name>

# Use it
docker buildx use cloud-<org>-<builder-name>
```

!!! info "Free Tier Available"
    Docker Build Cloud has a free tier with limited build minutes. Perfect for occasional multi-arch builds.

---

## Bonus: Quick Reference

```bash
# Prune everything (reclaim disk space)
docker system prune -a --volumes

# See real-time resource usage
docker stats

# Copy files from container
docker cp container:/path/file ./local/

# Export container filesystem
docker export container > container.tar

# Inspect image layers
docker history --no-trunc myimage

# Run one-off command in new container
docker run --rm -it alpine sh
```
