#pragma once
#include <stdint.h>

void
crc64(uint64_t *crc, const void *data, size_t len);
