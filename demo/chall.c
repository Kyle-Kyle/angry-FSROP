#include <stdio.h>

void write_what_where()
{
	unsigned long addr;

	printf("addr:");
	read(0, &addr, sizeof(addr));

	printf("do it:");
	read(0, (void *)addr, 0x100);
}

int main()
{
	setbuf(stdout, NULL);
	printf("puts @ %#lx\n", (unsigned long)puts);

	while(1) write_what_where();

}
