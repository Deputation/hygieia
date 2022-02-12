#include "utils.h"

void* Utils::driver_start = nullptr;
void* Utils::driver_end = nullptr;

bool Utils::is_inside_hygieia(void* virtual_address) {
  if (virtual_address < driver_start) {
    return false;
  }

  if (virtual_address > driver_end) {
    return false;
  }

  return true;
}

void* Utils::to_virtual(void* physical_address) {
  PHYSICAL_ADDRESS buffer;
  buffer.QuadPart = reinterpret_cast<uint64_t>(physical_address);
  return MmGetVirtualForPhysical(buffer);
}

void* Utils::to_physical(void* virtual_address) {
  return reinterpret_cast<void*>(
      MmGetPhysicalAddress(virtual_address).QuadPart);
}
