.globl my_system
my_system:
pushl %ebx
movl %esp, %ebx
pushl %ecx
movl %eax, %ecx
pusha
#call my_system2		# verify memory perms
cmpl $0x0, %eax	
jz normal

popa
popl %ecx
popl %ebx
movl $0x1, %eax		# force an exit() syscall
jmp *old_system

normal:
popa
popl %ecx
popl %ebx
jmp *old_system 
