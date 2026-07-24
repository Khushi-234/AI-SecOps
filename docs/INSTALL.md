# Installation Guide

This guide provides instructions for setting up the AI-SecOps framework on various platforms and environments.

## Platform and Environment Support

AI-SecOps is designed to run on both CPU and GPU (NVIDIA CUDA) environments across Linux and Windows platforms.

### 1. Ubuntu CPU
To install the base framework along with Linux-specific optimizations (such as `uvloop`), execute:
```bash
pip install -r requirements/linux.txt
```

### 2. Ubuntu GPU
For environments equipped with NVIDIA GPUs, first install the Linux dependencies, followed by the GPU-specific packages:
```bash
pip install -r requirements/linux.txt
pip install -r requirements/gpu.txt
```

### 3. Windows

#### Windows CPU
To install the CPU version on Windows:
```cmd
pip install -r requirements/windows.txt
```

#### Windows GPU
For environments with NVIDIA GPUs on Windows, install the Windows dependencies followed by the GPU packages:
```cmd
pip install -r requirements/windows.txt
pip install -r requirements/gpu.txt
```

### 4. Development Environment
To install tools required for testing, formatting, and linting (such as `pytest`, `black`, `ruff`, and `mypy`):
```bash
pip install -r requirements/dev.txt
```
