#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(){
    srand(time(NULL));
    int random_number = rand() % 4096;
    void *base = malloc(1337 + random_number);
    sleep(10*60*60);
    exit(EXIT_FAILURE);
}