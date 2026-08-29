#include <stdio.h>

int add(int x, int y) {
    return x + y;
}

int main(void) {
    int a = 3, b = 4;
    int result = add(a, b);
    printf("add(%d, %d) = %d\n", a, b, result);
    return 0;
}
