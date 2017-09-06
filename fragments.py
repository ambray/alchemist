#!/usr/bin/env python

from mako.template import Template


win32_c = {
    'allocate': ("${buffer} = (${type})HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ${size})", "${buffer} == NULL"),
    'deallocate': ("HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, ${buffer})", None),
}
