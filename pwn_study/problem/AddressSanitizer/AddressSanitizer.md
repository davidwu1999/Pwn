# AddressSanitizer
# core algorithm
## shadow memory
The memory addresses returned by the malloc function are typically aligned to at least 8 bytes. This leads to the observation that any aligned 8-byte sequence of application heap memory is in one of 9 different states: the first k (0 ≤ k ≤ 8) bytes are addressable and the remaining 8 − k bytes are not. This state can be encoded into a single byte of shadow memory.  
the shadow byte is computed as (Addr>>3)+Offset.  
We use the following encoding for each shadow byte: 0 means that all 8 bytes of the corresponding application memory region are addressable; k (1 ≤ k ≤ 7) means that the first k bytes are addressible; any negative value indi- cates that the entire 8-byte word is unaddressable. We use different negative values to distinguish between different kinds of unaddressable memory (heap redzones, stack redzones, global redzones, freed memory).  
## red zone
The memory regions inside the allocator are organized as an array of freelists corresponding to a range of object sizes. When a freelist that corresponds to a requested object size is empty, a large group of memory regions with their redzones is allocated from the operating system (using, e.g., mmap). For n regions we allocate n + 1 redzones, such that the right redzone of one region is typically a left redzone of another region:   

| rz1  | mem1 | rz2 | mem2 | rz3 | mem3 | rz4
## heap after free
The free function poisons the entire memory region and puts it into quarantine, such that this region will not be allocated by malloc any time soon. Currently, the quarantine is implemented as a FIFO queue which holds a fixed amount of memory at any time.
## parameters
### Depth of stack unwinding (default: 30). 

On every call to malloc and free the tool needs to unwind the call stack so that error messages contain more information. This option affects the speed of the tool, especially if the tested application is malloc-intensive. It does not affect the memory footprint or the bug-finding ability, but short stack traces are often not enough to analyze an error message.
### Quarantine size (default: 256MB).
This value con- trols the ability to find heap-use-after-free bugs (see Sec- tion 3.5). It does not affect performance.
### Size of the heap redzone (default: 128 bytes).
This option affects the ability to find heap-buffer-overflow bugs (see Section 3.5). Large values may lead to sig- nificant slowdown and increased memory usage, espe- cially if the tested program allocates many small chunks of heap memory. Since the redzone is used to store the malloc call stack, decreasing the redzone automatically decreases the maximal unwinding depth.