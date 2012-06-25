#ifndef __ASM_GENERIC_MODULE_H
#define __ASM_GENERIC_MODULE_H

/*
 * Many architectures just need a simple module
 * loader without arch specific data.
 */
struct mod_arch_specific
{
};

#ifdef CONFIG_64BIT
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#else
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#endif

#endif /* __ASM_GENERIC_MODULE_H */
