#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;
  // printf("%d %s\n", argc,*argv);
  for (i = 0; i < argc; i++){
    // printf("%d\n",i);
    printf ("%s ", argv[i]);
  }
  printf ("\n");

  return EXIT_SUCCESS;
}
