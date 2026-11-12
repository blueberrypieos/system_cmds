/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#ifndef PIE_CHPASS_OPEN_DIRECTORY_H
#define PIE_CHPASS_OPEN_DIRECTORY_H

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>

void setrestricted(CFDictionaryRef);
ODRecordRef odGetUser(CFStringRef, CFStringRef, CFStringRef, CFDictionaryRef *);
void odUpdateUser(ODRecordRef, CFDictionaryRef, CFDictionaryRef);

#endif
