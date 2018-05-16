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
