.section ".text", "ax"

.global gdb_elf_load
gdb_elf_load:
	//ident
	mv s0, a0
	//ecall
	mv s1, a1
	//&argc
	mv s2, a2
	//argv
	mv s3, a3
	//auxvec
	mv s4, a4
	
loop:
	mv sp, s2
	mv a7, s0
	mv a6, s1
	ecall
	
	j loop
