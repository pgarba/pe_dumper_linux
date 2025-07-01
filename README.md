# PE Dumper for Linux

A tool to extract and analyze Portable Executable (PE) files from processes running under Wine on Linux.

## Features

- Dump the in-memory PE file of a process executed with Wine
- Analyze PE headers and sections

## Installation

Clone the repository:

```bash
git clone https://github.com/pgarba/pe_dumper_linux.git
cd pe_dumper_linux
```

Build the project (using CMake):

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

To dump a PE file from a running Wine process:

```bash
./pedumper <pid> <exe_name>
```

Example:

```bash
./pedumper 1111 test.exe
```

- `<pid>`: Process ID of the Wine process running the PE file
- `<exe_name>`: Name of the executable to dump

## Requirements

- Linux system
- Wine
- C++ compiler (e.g., clang++ or g++)
- CMake

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.