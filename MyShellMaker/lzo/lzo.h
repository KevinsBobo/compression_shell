#ifndef _LZO_H
#define _LZO_H

extern "C" int _stdcall compress(void *src, unsigned src_len, void *dst);
extern "C" int _stdcall decompress(void *src, unsigned src_len, void *dst);

#endif