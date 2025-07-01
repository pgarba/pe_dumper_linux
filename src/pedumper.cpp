#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

#include "pe64.h" // Include your PE64 header file

// Get exe name from /proc/<pid>/status
std::string get_executable_name(pid_t pid) {
  std::ostringstream path;
  path << "/proc/" << pid << "/status";

  std::ifstream status_file(path.str());
  if (!status_file.is_open()) {
    std::cerr << "Failed to open status file for PID " << pid << "\n";
    return "";
  }

  std::string line;
  while (std::getline(status_file, line)) {
    if (line.find("Name:") == 0) {
      // Extract the executable name
      size_t colon_pos = line.find(':');
      if (colon_pos != std::string::npos) {
        return line.substr(colon_pos + 1);
      }
    }
  }

  std::cerr << "Executable name not found for PID " << pid << "\n";
  return "";
}

uint64_t get_process_base_address(pid_t pid, const char *exe_name) {
  std::ostringstream path;
  path << "/proc/" << pid << "/maps";

  std::ifstream maps_file(path.str());
  if (!maps_file.is_open()) {
    std::cerr << "Failed to open maps file for PID " << pid << "\n";
    return 0;
  }

  std::string line;
  while (std::getline(maps_file, line)) {
    if (line.find(exe_name) != std::string::npos) {
      // Extract the base address from the line
      size_t dash_pos = line.find('-');
      if (dash_pos != std::string::npos) {
        std::string base_addr_str = line.substr(0, dash_pos);
        return std::stoull(base_addr_str, nullptr, 16);
      }
    }
  }

  std::cerr << "Base address not found for " << exe_name << " in PID " << pid
            << "\n";
  return 0;
}

// Helper to read memory from another process using process_vm_readv
bool read_process_memory(pid_t pid, void *address, void *buffer, size_t size) {
  struct iovec local_iov = {buffer, size};
  struct iovec remote_iov = {(void *)address, size};
  ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
  return nread == (ssize_t)size;
}

// Helper to get PE image size from headers
size_t get_pe_image_size(uint8_t *pe_base) {
  IMAGE_DOS_HEADER *dos_hdr = reinterpret_cast<IMAGE_DOS_HEADER *>(pe_base);
  uint32_t pe_offset = dos_hdr->e_lfanew;

  const IMAGE_NT_HEADERS64 *nt_hdr =
      reinterpret_cast<const IMAGE_NT_HEADERS64 *>(pe_base + pe_offset);

  // Get image size by parsing the section headers and calculating the total
  // size
  if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
    std::cerr << "Invalid PE signature sizeof IMAGE_DOS_HEADER:" << std::hex
              << sizeof(IMAGE_DOS_HEADER) << "\n";
    return 0;
  }

  // Read process memory to get the section headers
  size_t image_size = 0;
  PIMAGE_SECTION_HEADER psectionheader = (PIMAGE_SECTION_HEADER)(nt_hdr + 1);

  std::cout << "Number of sections: " << nt_hdr->FileHeader.NumberOfSections
            << "\n";

  image_size =
      psectionheader[nt_hdr->FileHeader.NumberOfSections - 1].VirtualAddress +
      psectionheader[nt_hdr->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

  return image_size;
}

// Dump PE file from process memory
bool dump_pe_from_process(pid_t pid, void *va, const std::string &out_path) {
  // Read DOS header to get PE header offset
  std::vector<uint8_t> dos_header(sizeof(IMAGE_DOS_HEADER));
  if (!read_process_memory(pid, va, dos_header.data(), dos_header.size())) {
    std::cerr << "Failed to read DOS header\n";
    return false;
  }

  if (dos_header[0] != 'M' || dos_header[1] != 'Z') {
    std::cerr << "Invalid DOS header: MZ signature not found\n";
    return false;
  }

  // Use structs to parse the DOS header
  IMAGE_DOS_HEADER *dos_hdr =
      reinterpret_cast<IMAGE_DOS_HEADER *>(dos_header.data());
  if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
    std::cerr << "Invalid DOS header: e_magic mismatch\n";
    return false;
  }

  uint32_t pe_offset = dos_hdr->e_lfanew;

  // Read the PE header
  std::vector<uint8_t> pe_header(sizeof(IMAGE_NT_HEADERS64));
  if (!read_process_memory(pid, (uint8_t *)va + pe_offset, pe_header.data(),
                           pe_header.size())) {
    std::cerr << "Failed to read PE header\n";
    return false;
  }

  IMAGE_NT_HEADERS64 *nt_hdr =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(pe_header.data());

  if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
    std::cerr << "Invalid PE header: Signature mismatch\n";
    return false;
  }

  // Check if it's a 64-bit PE
  if (nt_hdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
    std::cerr << "Unsupported PE format: Not a 64-bit image\n";
    return false;
  }

  // Get the size of the image
  uint8_t pe_header_dump[0x1000];
  if (!read_process_memory(pid, (uint8_t *)va, pe_header_dump,
                           sizeof(pe_header_dump))) {
    std::cerr << "Failed to read PE header dump\n";
    return false;
  }

  size_t image_size = get_pe_image_size((uint8_t *)pe_header_dump);
  if (image_size == 0) {
    std::cerr << "Failed to determine PE image size\n";
    return false;
  }

  std::cout << "PE image size: 0x" << std::hex << image_size << " bytes\n";

  // Read the full image
  std::vector<uint8_t> image(image_size);
  if (!read_process_memory(pid, va, image.data(), image_size)) {
    std::cerr << "Failed to read PE image\n";
    return false;
  }

  // Write to file
  std::ofstream ofs(out_path, std::ios::binary);
  if (!ofs) {
    std::cerr << "Failed to open output file\n";
    return false;
  }
  ofs.write((const char *)image.data(), image.size());
  ofs.close();
  return true;
}

bool fix_pe_dump(const std::string &file_path) {
  // Open file for read/write in binary mode
  std::fstream fs(file_path, std::ios::in | std::ios::out | std::ios::binary);
  if (!fs) {
    std::cerr << "Failed to open file for fixing: " << file_path << "\n";
    return false;
  }

  fs.seekg(0, std::ios::end);
  std::streamsize file_size = fs.tellg();
  fs.seekg(0, std::ios::beg);

  // Read file into a buffer
  std::vector<uint8_t> buffer(file_size);
  fs.read(reinterpret_cast<char *>(buffer.data()), file_size);
  if (!fs) {
    std::cerr << "Failed to read file into buffer\n";
    return false;
  }

  // Read DOS header
  PIMAGE_DOS_HEADER dos_hdr =
      reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
  if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
    std::cerr << "Invalid DOS header: e_magic mismatch\n";
    return false;
  }

  // Read NT headers
  IMAGE_NT_HEADERS64 *nt_hdr =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(buffer.data() + dos_hdr->e_lfanew);
  if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
    std::cerr << "Invalid NT header: Signature mismatch\n";
    return false;
  }

  PIMAGE_SECTION_HEADER psectionheader = (PIMAGE_SECTION_HEADER)(nt_hdr + 1);
  for (int i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {

    // Calculate the size of the section
    if (i < nt_hdr->FileHeader.NumberOfSections - 1) {
      psectionheader[i].Misc.VirtualSize =
          psectionheader[i + 1].VirtualAddress -
          psectionheader[i].VirtualAddress;
    }

    psectionheader[i].PointerToRawData = psectionheader[i].VirtualAddress;
    psectionheader[i].SizeOfRawData = psectionheader[i].Misc.VirtualSize;
  }

  // Write the fixed buffer back to the file
  fs.seekp(0, std::ios::beg);
  fs.write(reinterpret_cast<const char *>(buffer.data()), file_size);
  if (!fs) {
    std::cerr << "Failed to write fixed buffer back to file\n";
    return false;
  }

  fs.close();
  return true;
}

// Example usage
int main(int argc, char *argv[]) {
  // Get PID and VA from command line arguments or hardcode for testing
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <pid> <exe_name>\n";
    return 1;
  }
  // Convert command line arguments to pid_t and uint64_t
  pid_t pid = std::stoi(argv[1]);

  // Get the executable name
  std::string exe_name = argv[2];

  std::cout << "Executable name: " << exe_name << "\n";

  // Get the base address of the process
  uint64_t base_address = get_process_base_address(pid, exe_name.c_str());
  if (base_address == 0) {
    std::cerr << "Failed to get base address for " << exe_name << " in PID "
              << pid << "\n";
    return 1;
  }

  std::cout << "Base address: 0x" << std::hex << base_address << "\n";

  if (dump_pe_from_process(pid, (void *)base_address, "dumped_pe.exe")) {
    std::cout << "PE dumped successfully\n";

    // Fix the dumped PE file
    if (fix_pe_dump("dumped_pe.exe")) {
      std::cout << "PE file fixed successfully\n";
    } else {
      std::cerr << "Failed to fix PE file\n";
    }
  } else {
    std::cerr << "Failed to dump PE\n";
  }
  return 0;
}