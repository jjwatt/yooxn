/*
Copyright (c) 2022-2025 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#define RAM_PAGES 0x10

int system_error(char *msg, const char *err);
int system_boot(Uint8 *ram, char *rom_path, int has_args);
int system_reboot(int soft);

Uint8 system_dei(Uint8 addr);
void system_deo(Uint8 addr);
