.section ".text", "ax"

.global gdb_elf_load
gdb_elf_load:
	//ident
	mv s0, a0
	//ecall
	mv s1, a1
	//&argc
	mv s2, a2
	
loop:
	mv sp, s2
	mv a7, s0
	mv a6, s1
	ecall
	
	j loop

.global sd_elf_load
sd_elf_load:
	//ident
	mv s0, a0
	//ecall
	mv s1, a1
	//&argc
	mv s2, a2
	//entry point
	mv s3, a3
	
	mv sp, s2
	mv a7, s0
	mv a6, s1

	jalr a3
