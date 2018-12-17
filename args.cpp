#include <stdio.h>
#include <stdlib.h>
#include <endian.h>

int main(int argc, char *argv[])
{
	for (int count = 0; count < argc; count++)
		fprintf(stderr, "%d: %s\n", count, argv[count]);

	unsigned int magic = strtol(argv[1], 0, 16);
	unsigned int size = atol(argv[2]);
	unsigned int entry = strtol(argv[3], 0, 16);
	unsigned int crc = strtol(argv[4], 0, 16);

	FILE *fp = fopen("header.bin", "wb");
	fprintf(stderr, "magic %08x, size %d, entry %08x, crc %08x\n", magic, size, entry, crc);

	magic = htobe32(magic);
	size = htobe32(size);
	entry = htobe32(entry);
	crc = htobe32(crc);

	fwrite(&magic, 1, 4, fp);
	fwrite(&size, 1, 4, fp);
	fwrite(&crc, 1, 4, fp);
	fwrite(&entry, 1, 4, fp);

	fclose(fp);
	return 0;
}

