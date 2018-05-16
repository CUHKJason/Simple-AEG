# Simple-AEG

Simple implementation of AEG

Usage
-----

1. `vul.c`:
    ```
    #include <stdio.h>
    #include <unistd.h>
    #include <string.h>

    char buf[100];

    int sample_func() {
        char name[10] = {0};
        read(0, buf, 307);
        strcpy(name, buf);
        printf("input: %s\n", name);
    }

    int main(void)
    {
        printf("Running...\n");
        sample_func();
        printf("Done.\n");
    }
    ```
2. complie `vul.c`:
    ```
    gcc vul.c -o vul -m32 -g -z execstack
    ```
3. `my_aeg.py`:
    ```
    from aeg import SimpleAEG
    import sys
    
    if len(sys.argv) > 1:
        binary = SimpleAEG(sys.argv[1])
        binary.attack()
    else:
        print "%s: <binary>" % sys.argv[0]
    ```

Dependences
----

- angr
- pwntools

Todo
----
- ROP (ret2libc)

Reference
----
- [AEG implementation from YSc21](https://github.com/YSc21/aegg)
- [angr-doc/examples/insomnihack_aeg](https://github.com/angr/angr-doc/blob/master/examples/insomnihack_aeg/)
- [(State of) The Art of War: Offensive Techniques in Binary Analysis](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf)
- [AEG: Automatic Exploit Generation](http://repository.cmu.edu/cgi/viewcontent.cgi?article=1239&context=ece)
