#include <stdio.h>
using namespace std;
char* get_quote (char* spid);
int main(int argc, char *argv[])
{
  char* quote = get_quote("3415A239C3B68EF66EAD98B1A2D01E2A");
  printf("\n\n%s\n\n", quote);

}
