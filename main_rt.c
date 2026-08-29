#include <stdio.h>

__attribute__((noinline))
int add(int x, int y) {
    return x + y;
}

int main(void) {
    volatile int a = 3, b = 4; // volatile defeats compile-time constant folding
    int result = add(a, b);
    printf("add(%d, %d) = %d\n", a, b, result);
    return 0;
}
