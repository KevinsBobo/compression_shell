#include <windows.h>

typedef LPVOID (WINAPI *PFN_GetProcAddress)(
_In_ HMODULE hModule,
_In_ LPCSTR lpProcName
);

typedef HMODULE
(WINAPI* PFN_LoadLibraryA)(
_In_ LPCSTR lpLibFileName
);

typedef LPVOID
(WINAPI* PFN_VirtualAlloc)(
_In_opt_ LPVOID lpAddress,
_In_ SIZE_T dwSize,
_In_ DWORD flAllocationType,
_In_ DWORD flProtect
);

typedef BOOL(WINAPI* PFN_VirtualFree)(
_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
_In_ SIZE_T dwSize,
_In_ DWORD dwFreeType
);

typedef 
BOOL
(WINAPI* PFN_VirtualProtect)(
_In_ LPVOID lpAddress,
_In_ SIZE_T dwSize,
_In_ DWORD flNewProtect,
_Out_ PDWORD lpflOldProtect
);

typedef struct tagPFN_APIS 
{
  PFN_GetProcAddress m_pfnGetProcAddress;
  PFN_LoadLibraryA m_pfnLoadLibrary;
  PFN_VirtualAlloc m_pfnVirtualAlloc;
  PFN_VirtualFree m_pfnVirtualFree;
  PFN_VirtualProtect m_pfnVirtualProtect;
}PFNAPIS, *PPFNAPIS;

BOOL InitPfnApis(PPFNAPIS pAois);
HMODULE GetKernelBase();
DWORD MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
PBYTE GetSourcePE(PPFNAPIS pAois);
HMODULE GetImageBaseAdress();
PBYTE LoadPE(PPFNAPIS pAois, PBYTE pPeData);
void * __cdecl mymemccpy(
  void * dest,
  const void * src,
  int c,
  unsigned count
  );

int __cdecl mymemcmp(
  const void * buf1,
  const void * buf2,
  size_t count
  );
void * __cdecl mymemset(
  void *dst,
  int val,
  size_t count
  );


void * __cdecl mymemcpy(
  void * dst,
  const void * src,
  size_t count
  );
typedef struct tagConfigInfo
{
  DWORD m_dwCompressSize; //压缩数据的大小
  DWORD m_dwDecompressSize; //解压缩数据的大小
}CONFIGINFO, *PCONFIGINFO;