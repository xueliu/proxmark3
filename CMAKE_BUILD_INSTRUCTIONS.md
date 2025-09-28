# Building with CMake in Docker

This document provides instructions on how to build the ARM firmware using the new CMake build system within the provided Docker environment.

### 1. Build `fpga_compress`

Before running CMake, you must build the `fpga_compress` tool, which is a dependency for the firmware build.

```bash
make -C tools/fpga_compress
```

### 2. Choose a Docker Environment

Navigate to one of the distribution-specific directories within the `docker` directory. For example:

```bash
cd docker/debian-12-bookworm
```

### 3. Build the Docker Image

Run the `build.sh` script to build the Docker image. This script will install all the necessary dependencies, including `cmake` and the ARM toolchain.

```bash
../build.sh
```

### 4. Start the Docker Container

Run the `run.sh` script to start an interactive container. The project directory will be automatically mounted inside the container at `/home/rrg/proxmark3`.

```bash
../run.sh
```

You will now be inside the Docker container's shell.

### 5. Configure the CMake Build

Inside the container, create a build directory and run CMake to configure the project. We will use the `toolchain-arm-none-eabi.cmake` file for cross-compilation.

```bash
# Navigate to the project root within the container
cd /home/rrg/proxmark3

# Create a build directory
mkdir -p build && cd build

# Configure the build with CMake
# This command points to the root of the project and specifies the toolchain file.
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake
```

#### Optional: Customize the Platform

You can specify a different target platform using the `PLATFORM` variable, similar to the old Makefile system. For example, to build for `PM3GENERIC`:

```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake -DPLATFORM=PM3GENERIC
```

You can also enable or disable extra features:
```bash
# Example: Enable the Bluetooth addon feature
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake -DPLATFORM_EXTRAS_BTADDON=ON
```

### 6. Compile the Firmware

Once CMake has successfully configured the project, you can build the firmware by running `make` inside the `build` directory.

```bash
make
```

Alternatively, you can use the `cmake --build` command, which is platform-agnostic:

```bash
cmake --build .
```

### 7. Locate the Build Artifacts

The compiled firmware files (`fullimage.elf`, `fullimage.s19`) will be located in the `build/armsrc/` directory. You can access these files from both inside and outside the Docker container, as the project directory is mounted.