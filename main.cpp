#include <iostream>
#include <unicorn/unicorn.h>
#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

// memory address where emulation starts
#define ADDRESS 0x1000000
#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"

static void hook_mem64(uc_engine *uc, uc_mem_type type,
                       uint64_t address, int size, int64_t value, void *user_data) {
    switch (type) {
        default:
            break;
        case UC_MEM_READ:
            printf(">>> Memory is being READ at 0x%" PRIx64 ", data size = %u\n",
                   address, size);
            break;
        case UC_MEM_WRITE:
            printf(">>> Memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n",
                   address, size, value);
            break;
    }
}

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
    printf(">>> RIP is 0x%" PRIx64 "\n", rip);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

static void test_x86_64(void) {

    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t rax = 0x71f3029efd49d41d;
    int64_t rbx = 0xd87b45277f133ddb;
    int64_t rcx = 0xab40d1ffd8afc461;
    int64_t rdx = 0x919317b4a733f01;
    int64_t rsi = 0x4c24e753a17ea358;
    int64_t rdi = 0xe509a57d2571ce96;
    int64_t r8 = 0xea5b108cc2b9ab1f;
    int64_t r9 = 0x19ec097c8eb618c1;
    int64_t r10 = 0xec45774f00c5f682;
    int64_t r11 = 0xe17e9dbec8c074aa;
    int64_t r12 = 0x80f86a8dc0f6d457;
    int64_t r13 = 0x48288ca5671c5492;
    int64_t r14 = 0x595f72f6e4017f6e;
    int64_t r15 = 0x1efd97aea331cccc;

    int64_t rsp = ADDRESS + 0x200000;


    printf("Emulate x86_64 code\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64, sizeof(X86_CODE64) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_R9, &r9);
    uc_reg_write(uc, UC_X86_REG_R10, &r10);
    uc_reg_write(uc, UC_X86_REG_R11, &r11);
    uc_reg_write(uc, UC_X86_REG_R12, &r12);
    uc_reg_write(uc, UC_X86_REG_R13, &r13);
    uc_reg_write(uc, UC_X86_REG_R14, &r14);
    uc_reg_write(uc, UC_X86_REG_R15, &r15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions in the range [ADDRESS, ADDRESS+20]
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, ADDRESS, ADDRESS + 20);

    // tracing all memory WRITE access (with @begin > @end)
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);

    // tracing all memory READ access (with @begin > @end)
    uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);
    printf(">>> RBX = 0x%" PRIx64 "\n", rbx);
    printf(">>> RCX = 0x%" PRIx64 "\n", rcx);
    printf(">>> RDX = 0x%" PRIx64 "\n", rdx);
    printf(">>> RSI = 0x%" PRIx64 "\n", rsi);
    printf(">>> RDI = 0x%" PRIx64 "\n", rdi);
    printf(">>> R8 = 0x%" PRIx64 "\n", r8);
    printf(">>> R9 = 0x%" PRIx64 "\n", r9);
    printf(">>> R10 = 0x%" PRIx64 "\n", r10);
    printf(">>> R11 = 0x%" PRIx64 "\n", r11);
    printf(">>> R12 = 0x%" PRIx64 "\n", r12);
    printf(">>> R13 = 0x%" PRIx64 "\n", r13);
    printf(">>> R14 = 0x%" PRIx64 "\n", r14);
    printf(">>> R15 = 0x%" PRIx64 "\n", r15);

    uc_close(uc);
}

void test_capstone() {
    size_t count;

    cs_insn *insn;
    static csh handle;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

    count = cs_disasm(handle, (unsigned char *) X86_CODE64, sizeof(X86_CODE64) - 1, 0x1000, 0, &insn);
    if (count) {
        size_t j;
        printf("****************\n");
        printf("Disasm:\n");
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        printf("0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disasm given code!\n");
        abort();
    }
}

void test_keystone(const char *assembly) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (ks_asm(ks, assembly, 0, &encode, &size, &count)) {
        printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(ks));
    } else {
        size_t i;

        printf("%s = ", assembly);
        for (i = 0; i < size; i++) {
            printf("%02x ", encode[i]);
        }
        printf("\n");
        printf("Assembled: %lu bytes, %lu statements\n\n", size, count);
    }

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);
}

int main(int argc, char **argv, char **envp) {
    test_keystone("mov eax,1;mov ebx,1");
    test_x86_64();
    test_capstone();
    system("pause");
    return 0;
}
