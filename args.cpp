#include <stdio.h>
#include <stdlib.h>

#ifdef __APPLE__

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else
#include <endian.h>
#endif

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
	fwrite(&entry, 1, 4, fp);
	fwrite(&crc, 1, 4, fp);

	fclose(fp);
	return 0;
}

