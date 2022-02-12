#include <ntddk.h>
#include <intrin.h>

#include "log.h"
#include "ia32.h"
#include "utils.h"

template <typename t>
inline t find_pattern(const char* pattern, const char* mask, void* start,
                      size_t length) {
  const auto data = static_cast<const char*>(start);
  const auto pattern_length = strlen(mask);

  for (auto i = 0; i <= length - pattern_length; i++) {
    bool found = true;

    for (auto j = 0; j < pattern_length; j++) {
      if (!MmIsAddressValid(reinterpret_cast<void*>(
              reinterpret_cast<uintptr_t>(start) + i + j))) {
        found = false;
        break;
      }

      if (data[i + j] != pattern[j] && mask[j] != '?') {
        found = false;
        break;
      }
    }

    if (found) {
      return (t)(reinterpret_cast<uintptr_t>(start) + i);
    }
  }

  return (t)(nullptr);
}

uint64_t scanned_memory = 0;
auto allocated_name = "iqvw64e.sys";
auto allocated_timestamp = "\xC3\xEA\x84\x52";

void scan_page(void* virtual_page) {
  __try {
    auto timestamp = find_pattern<void*>(allocated_timestamp, "xxxx",
                                         virtual_page, PAGE_SIZE);
    auto name = find_pattern<void*>(allocated_name, "xxxxxxxxxxx", virtual_page,
                                    PAGE_SIZE);

    if (name && !Utils::is_inside_hygieia(name)) {
      LOG("Found vulnerable driver name outside "
          "Hygieia @%p",
          name);
    } else if (name && Utils::is_inside_hygieia(name)) {
      LOG("Found vulnerable driver name **inside** "
          "Hygieia @%p",
          name);
    }

    if (timestamp && !Utils::is_inside_hygieia(timestamp)) {
      LOG("Found vulnerable driver timestamp "
          "outside Hygieia @%p",
          timestamp);
    } else if (timestamp && Utils::is_inside_hygieia(timestamp)) {
      LOG("Found vulnerable driver timestamp "
          "**inside** Hygieia @%p",
          timestamp);
    }

    scanned_memory += PAGE_SIZE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}

void scan_region(void* virtual_page, size_t size) {
  UNREFERENCED_PARAMETER(virtual_page);

  if (size == PAGE_SIZE) {
    scan_page(virtual_page);

    return;
  }

  for (auto i = 0; i < size; i += PAGE_SIZE) {
    auto base = reinterpret_cast<uint8_t*>(virtual_page) + i;

    scan_page(base);
  }
}

void walk_ptes(pte_64* table) {
  if (!MmIsAddressValid(table) || !table) {
    LOG("Invalid PT table...");

    return;
  }

  for (auto pte_index = 0; pte_index < 512; pte_index++) {
    __try {
      if (!table[pte_index].present) {
        continue;
      }

      auto page_physical_address = table[pte_index].page_frame_number
                                   << PAGE_SHIFT;

      auto virtual_page =
          Utils::to_virtual(reinterpret_cast<void*>(page_physical_address));

      if (!MmIsAddressValid(virtual_page) || !virtual_page) {
        continue;
      }

      scan_region(virtual_page, PAGE_SIZE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      LOG("Error accessing PTE #%d", pte_index);
    }
  }
}

void walk_pdes(pde_64* table) {
  if (!MmIsAddressValid(table) || !table) {
    LOG("Invalid PD table...");

    return;
  }

  for (auto pde_index = 0; pde_index < 512; pde_index++) {
    __try {
      if (!table[pde_index].present) {
        continue;
      }

      if (table[pde_index].large_page) {
        // size = 0x40000

        auto page_physical_address = table[pde_index].page_frame_number
                                     << PAGE_SHIFT;
        auto virtual_page_address =
            Utils::to_virtual(reinterpret_cast<void*>(page_physical_address));

        scan_region(virtual_page_address, 0x200000);

        continue;
      }

      auto pde_physical_address = table[pde_index].page_frame_number
                                  << PAGE_SHIFT;

      auto virtual_pt_address =
          Utils::to_virtual(reinterpret_cast<void*>(pde_physical_address));

      if (!MmIsAddressValid(virtual_pt_address) || !virtual_pt_address) {
        continue;
      }

      walk_ptes(reinterpret_cast<pte_64*>(virtual_pt_address));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      LOG("Error accessing PDE #%d", pde_index);
    }
  }
}

void walk_pdptes(pdpte_64* table) {
  if (!MmIsAddressValid(table) || !table) {
    LOG("Invalid PDPT table...");

    return;
  }

  for (auto pdpt_index = 0; pdpt_index < 512; pdpt_index++) {
    __try {
      if (!table[pdpt_index].present) {
        continue;
      }

      if (table[pdpt_index].large_page) {
        // size = 0x40000000

        auto page_physical_address = table[pdpt_index].page_frame_number
                                     << PAGE_SHIFT;
        auto virtual_page_address =
            Utils::to_virtual(reinterpret_cast<void*>(page_physical_address));

        scan_region(virtual_page_address, 0x40000000);

        continue;
      }

      auto pdpt_physical_address = table[pdpt_index].page_frame_number
                                   << PAGE_SHIFT;

      auto virtual_pde_address =
          Utils::to_virtual(reinterpret_cast<void*>(pdpt_physical_address));

      if (!MmIsAddressValid(virtual_pde_address) || !virtual_pde_address) {
        continue;
      }

      walk_pdes(reinterpret_cast<pde_64*>(virtual_pde_address));

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      LOG("Error accessing PDPTE #%d", pdpt_index);
    }
  }
}

void walk_pml4es(pml4e_64* table) {
  if (!MmIsAddressValid(table) || !table) {
    LOG("Invalid PML4 table...");

    return;
  }

  for (auto pml4_index = 0; pml4_index < 512; pml4_index++) {
    __try {
      if (!table[pml4_index].present) {
        continue;
      }

      auto pml4_physical_address = table[pml4_index].page_frame_number
                                   << PAGE_SHIFT;

      auto virtual_pdpt_address =
          Utils::to_virtual(reinterpret_cast<void*>(pml4_physical_address));

      if (!MmIsAddressValid(virtual_pdpt_address) || !virtual_pdpt_address) {
        continue;
      }

      walk_pdptes(reinterpret_cast<pdpte_64*>(virtual_pdpt_address));

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      LOG("Error accessing PML4E #%d", pml4_index);
    }
  }
}

void entry(void* context) {
  UNREFERENCED_PARAMETER(context);

  LOG("Thread started!");

  LARGE_INTEGER time;
  KeQuerySystemTimePrecise(&time);

  cr3 kernel_directory;
  kernel_directory.flags = __readcr3();

  LOG("Physical address of page directory: %p",
      reinterpret_cast<void*>(kernel_directory.address_of_page_directory
                              << PAGE_SHIFT));

  LOG("Virtual address of page directory: %p ",
      Utils::to_virtual(reinterpret_cast<void*>(
          kernel_directory.address_of_page_directory << PAGE_SHIFT)));

  auto pml4_table =
      reinterpret_cast<pml4e_64*>(Utils::to_virtual(reinterpret_cast<void*>(
          kernel_directory.address_of_page_directory << PAGE_SHIFT)));

  walk_pml4es(pml4_table);

  LOG("Total scanned memory: %lld.", scanned_memory);

  LARGE_INTEGER new_time;
  KeQuerySystemTimePrecise(&new_time);

  auto total_100_nanoseconds_intervals = new_time.QuadPart - time.QuadPart;
  auto total_milliseconds_elapsed = total_100_nanoseconds_intervals / 10000;

  LOG("Scan completed in %lld ms.", total_milliseconds_elapsed);

  PsTerminateSystemThread(STATUS_SUCCESS);
}

void driver_unload(PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);

  LOG("Unloaded!");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);

  driver_object->DriverUnload = driver_unload;

  LOG("Driver started @%p - %p", driver_object->DriverStart,
      reinterpret_cast<void*>(driver_object->DriverSize));

  Utils::driver_start = driver_object->DriverStart;
  Utils::driver_end =
      reinterpret_cast<void*>(reinterpret_cast<size_t>(Utils::driver_start) +
                              driver_object->DriverSize);

  HANDLE discard;
  return PsCreateSystemThread(&discard, THREAD_ALL_ACCESS, nullptr, NULL,
                              nullptr, entry, nullptr);
}