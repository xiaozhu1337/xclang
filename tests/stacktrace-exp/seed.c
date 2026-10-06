/// Walks a crash's stack with dbghelp's StackWalk64 from the exception
/// context twice: with STACKFRAME64 zeroed, as LLVM's LocalPrintStackTrace
/// leaves it when given a context, and seeded from that context.

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#if defined(_M_IX86)
#define MACHINE IMAGE_FILE_MACHINE_I386
#elif defined(_M_X64)
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM64)
#define MACHINE IMAGE_FILE_MACHINE_ARM64
#endif

static int walk(const CONTEXT *Original, int Seed) {
  STACKFRAME64 Frame = {0};
  CONTEXT Context = *Original;
  if (Seed) {
#if defined(_M_IX86)
    Frame.AddrPC.Offset = Context.Eip;
    Frame.AddrStack.Offset = Context.Esp;
    Frame.AddrFrame.Offset = Context.Ebp;
#elif defined(_M_X64)
    Frame.AddrPC.Offset = Context.Rip;
    Frame.AddrStack.Offset = Context.Rsp;
    Frame.AddrFrame.Offset = Context.Rbp;
#elif defined(_M_ARM64)
    Frame.AddrPC.Offset = Context.Pc;
    Frame.AddrStack.Offset = Context.Sp;
    Frame.AddrFrame.Offset = Context.Fp;
#endif
  }
  Frame.AddrPC.Mode = Frame.AddrStack.Mode = Frame.AddrFrame.Mode = AddrModeFlat;
  int Depth = 0;
  while (StackWalk64(MACHINE, GetCurrentProcess(), GetCurrentThread(), &Frame,
                     &Context, NULL, SymFunctionTableAccess64,
                     SymGetModuleBase64, NULL)) {
    if (Frame.AddrFrame.Offset == 0)
      break;
    char Buffer[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO *Symbol = (SYMBOL_INFO *)Buffer;
    Symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    Symbol->MaxNameLen = 255;
    DWORD64 Displacement = 0;
    const char *Name = SymFromAddr(GetCurrentProcess(), Frame.AddrPC.Offset,
                                   &Displacement, Symbol)
                           ? Symbol->Name
                           : "?";
    printf("  #%d 0x%llx %s\n", Depth++, (unsigned long long)Frame.AddrPC.Offset, Name);
  }
  if (!Depth)
    printf("  (StackWalk64 returned FALSE, error %lu)\n", GetLastError());
  return Depth;
}

static LONG WINAPI filter(EXCEPTION_POINTERS *Pointers) {
  SymSetOptions(SYMOPT_DEFERRED_LOADS);
  SymInitialize(GetCurrentProcess(), NULL, TRUE);
  printf("zeroed STACKFRAME64 (LLVM):\n");
  walk(Pointers->ContextRecord, 0);
  printf("seeded from the exception context:\n");
  walk(Pointers->ContextRecord, 1);
  fflush(stdout);
  ExitProcess(1);
}

__declspec(noinline) static void frame_c(void) { *(volatile int *)0 = 0; }
__declspec(noinline) static void frame_b(void) { frame_c(); }
__declspec(noinline) static void frame_a(void) { frame_b(); }

int main(void) {
  SetUnhandledExceptionFilter(filter);
  frame_a();
  return 0;
}
