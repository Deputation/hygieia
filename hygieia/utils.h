#pragma once

#include <ntddk.h>

#include "ia32.h"

namespace Utils {
extern void* driver_start;
extern void* driver_end;

bool is_inside_hygieia(void* virtual_address);

void* to_virtual(void* physical_address);
void* to_physical(void* virtual_address);
}  // namespace Utils