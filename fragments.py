#!/usr/bin/env python

from mako.template import Template

return_success = 0
return_failure = 1


windows_clang_defs = """

#ifndef _WIN32
typedef unsigned int DWORD;
typedef void*        HANDLE;
typedef int          BOOL;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef INFINITE
#define INFINITE ((DWORD)-1)
#endif
#ifndef WAIT_IO_COMPLETION
#define WAIT_IO_COMPLETION 0x000000C0L
#endif
${extern_function_defs}
#else
#include <Windows.h>
#endif

"""

# TODO: Add ZwWaitForSingleObject(...)
windows_wait_functions = {
    'WaitForSingleObject': {
        'prototype': "DWORD __stdcall ${function_name}(HANDLE, DWORD)",
        'invoke': "${function_name}(${param1}, ${param2})",
        'module': "Kernel32.dll",
        'runtime_only': False,
        'returns': {
            'success': '0 == ${return_value}',
            'failure': '0 != ${return_value}',
        }
    },
    'WaitForSingleObjectEx': {
        'prototype': "DWORD __stdcall ${function_name}(HANDLE, DWORD, BOOL)",
        'invoke': "${function_name}(${param1}, ${param2}, ${param3})",
        'module': "Kernel32.dll",
        'runtime_only': False,
        'returns': {
            'success': '0 == ${return_value} || WAIT_IO_COMPLETION == ${return_value}',
            'failure': '0 != ${return_value} && WAIT_IO_COMPLETION != ${return_value}'
        }
    }
}

windows_time_prims = {
    'Sleep': {
        'prototype': "void __stdcall ${function_name}(DWORD)",
        "returns": None,
        "module": "Kernel32.dll",
        "invoke": "${function_name}(${param1})",
        "runtime_only": False,
    },
    'CreateWaitableTimer': {

    },
    'SetWaitableTimer': {

    },
}

windows_misc_funcs = {
    'CloseHandle': {
        'prototype': ''
    },
    'CreateEventW': {

    }
}

windows_start_functions = {
    'thread': {
        'signature': "DWORD __stdcall ${functon_name}(void* ${variable_name})",
        'return': (0, 1),
        'wait_alertable': False,
    },

}

windows_entry_points = {
    'main': {
        'signature': 'int main(int argc, char** argv)',
        'return': (0, -1),
    },
    'WinMain': {
        'signature': 'int __stdcall WinMain(void* hInstance, void* hPrev, char* lpCmdline, int nCmdShow)',
        'return': (0, -1),
    },
    'DllMain': {
        'signature': "BOOL __stdcall DllMain(void* hmod, DWORD dwReason, void* lpReserved)",
        'return': ('TRUE', 'FALSE'),
    }
}

windows_mainloop_init = """
HANDLE         ${timer_name} = NULL;
HANDLE         ${quit_event_name} = NULL;
LARGE_INTEGER  ${timeout_var} = {0};

${timeout_var}.QuadPart = -1 * ${timeout_value_in_ms};

if(NULL == (${timer_name} = CreateWaitableTimerW(NULL, FALSE, NULL))) {
    return ${return_failure};
}

if(NULL == (${quit_event_name} = CreateEventW(NULL, FALSE, FALSE, NULL))) {
    CloseHandle(${timer_name});
    return ${return_failure};
}

"""


windows_mainloop_cleanup = """
    CloseHandle(${timer_name});
    CloseHandle(${quit_event_name});
"""

windows_mainloop = """
while(TRUE) {
    DWORD  dwRes = 0;
    HANDLE hWaitables[] = { ${timer_name}, ${quit_event_name} };
    
    dwRes = WaitForMultipleObjects(2, hWaitables, FALSE, INFINITE);
    switch(dwRes) {
    case 0: // timer
        ${invoke_work}
        break;
    case 1: // quit_event
        goto done;
    default:  // an error occurred
        goto done;
    
    }

}
done:

"""

windows_mainblock = """

DWORD __stdcall entry(void* p)
{
    ${main_loop_init}

    ${main_loop}
    
    ${main_loop_cleanup}

    return 0;
}

${main_signature}
{
    HANDLE hThread = NULL;
    DWORD  dwRes = 0;
    
    if(NULL == (hThread = CreateThread(NULL, 0, entry, NULL, 0, NULL))) {
        return ${return_failure};
    }

    if(0 != (dwRes = WaitForSingleObject(hThread, INFINITE))) {
        CloseHandle(hThread);
        return ${return_failure}; 
    }
     
    CloseHandle(hThread);
    return ${return_success};
}

"""

windows_composite = """
${includes_block}

${init_block}

% for capability in capabilities

${capability}

% endfor

${entry_function}

${main_block}

"""

