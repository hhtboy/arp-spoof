#pragma once

#include <stddef.h>
#include "arphdr.h"

Mac get_mac_address(const char *interface);

Ip get_ip_address(const char *interface);

