#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main(){
    srand(time(NULL));
    int random_number = rand();
    void *base = malloc(1024L * random_number * random_number);
    sleep(20*60*60);
    exit(EXIT_FAILURE);
}