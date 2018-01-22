#ifndef _LZO_H
#define _LZO_H

int _stdcall compress(void *src, unsigned src_len, void *dst);
int _stdcall decompress(void *src, unsigned src_len, void *dst);

#endif