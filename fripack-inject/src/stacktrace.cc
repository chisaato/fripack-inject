#include "stacktrace.h"

#ifdef __ANDROID__
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unwind.h>
#include <dlfcn.h>

namespace {

struct BacktraceState
{
    void** current;
    void** end;
};

static _Unwind_Reason_Code unwindCallback(struct _Unwind_Context* context, void* arg)
{
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = reinterpret_cast<void*>(pc);
        }
    }
    return _URC_NO_REASON;
}

}

size_t captureBacktrace(void** buffer, size_t max)
{
    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(unwindCallback, &state);

    return state.current - buffer;
}

void dumpBacktrace(std::ostream& os, void** buffer, size_t count)
{
    // Get current module base address
    Dl_info current_module_info;
    void* current_module_base = nullptr;
    if (dladdr(reinterpret_cast<const void*>(dumpBacktrace), &current_module_info)) {
        current_module_base = const_cast<void*>(current_module_info.dli_fbase);
    }

    for (size_t idx = 0; idx < count; ++idx) {
        const void* addr = buffer[idx];
        const char* symbol = "";

        Dl_info info;
        if (dladdr(addr, &info) && info.dli_sname) {
            symbol = info.dli_sname;
        }

        // Check if address is within current module
        if (current_module_base && info.dli_fbase == current_module_base) {
            uintptr_t offset = reinterpret_cast<uintptr_t>(addr) - reinterpret_cast<uintptr_t>(current_module_base);
            const char* module_name = current_module_info.dli_fname ?
                strrchr(current_module_info.dli_fname, '/') ? strrchr(current_module_info.dli_fname, '/') + 1 :
                current_module_info.dli_fname : "unknown.so";
            os << "  #" << std::setw(2) << idx << ": " << module_name << " + 0x" << std::hex << offset << std::dec << "  " << symbol << "\n";
        } else {
            os << "  #" << std::setw(2) << idx << ": " << addr << "  " << symbol << "\n";
        }
    }
}

std::string fripack::getBacktraceString()
{
    constexpr size_t max_frames = 64;
    void* buffer[max_frames];
    size_t count = captureBacktrace(buffer, max_frames);

    std::ostringstream oss;
    dumpBacktrace(oss, buffer, count);
    return oss.str();
}
#else
#include <string>

namespace fripack {
    std::string getBacktraceString() {
        return "Backtrace not supported on this platform.";
    }
}
#endif