# PE-Parser
This is a C-based CLI to parse PE headers. This is a self-education project.


## What did I learn so far?
When patching RELOC addresses you can't just load the PE header into memory; you have to accomodate for the size determined by the optionalheader's SizeOfImage field due to expansion of the data in memory (virutal size can be > disk size).

## Compiling
I wasted so much time trying to crawl through the PE header structure with incorrect offsets due to incorrect? definitions in winn.t deployed with the compiler I was using. Switching to x86_64-w64-mingw32-gcc fixed this for me using wsl ubuntu. (Note to self: Just use x86_64-w64-mingw32-gcc from now on.)