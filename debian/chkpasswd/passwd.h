/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#ifndef PIE_CHKPASSWD_PASSWD_H
#define PIE_CHKPASSWD_PASSWD_H

void checkpasswd(char *, char *);
int file_check_passwd(char *, char *);
int nis_check_passwd(char *, char *);
int od_check_passwd(const char *, const char *);
int pam_check_passwd(char *);

#endif
