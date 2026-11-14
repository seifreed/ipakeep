#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define main lvpatch_program_main
#include "lvpatch.c"
#undef main

static int init_result;
static int has_info;
static const char *info_description;
static uint32_t instruction;
static uint32_t written_instruction;
static int write_sticks;
static int write_count;

int jbclient_initialize_primitives(void) { return init_result; }
void *jbinfo_get_serialized(void) { return has_info ? (void *)1 : NULL; }
char *xpc_copy_description(void *object) {
    return object ? (char *)info_description : NULL;
}
uint32_t kread32(uint64_t address) {
    assert(looks_like_kptr(address));
    return instruction;
}
void kwrite32(uint64_t address, uint32_t value) {
    assert(looks_like_kptr(address));
    written_instruction = value;
    write_count++;
    if (write_sticks) instruction = value;
}

static int run(int argc, char **argv) { return lvpatch_program_main(argc, argv); }

static void reset_state(void) {
    init_result = 0;
    has_info = 0;
    info_description = NULL;
    instruction = INSN_MOV_W0_1;
    written_instruction = 0;
    write_sticks = 1;
    write_count = 0;
}

static void test_slide_parsing(void) {
    unsetenv("IPAKEEP_KSLIDE");
    assert(find_slide(NULL) == 0);
    assert(find_slide("slide: 0x1234000") == 0x1234000);
    assert(find_slide("slide: 0x40000000") == 0);
    assert(find_slide("kernel 0xfffffff007005000") == 0x1000);
    assert(looks_like_kptr(0xfffffff007000000ULL));
    assert(!looks_like_kptr(0xffffffffffffffffULL));
    assert(!looks_like_kptr(0));
}

static void test_read_only_and_argument_errors(void) {
    char *plain[] = {"lvpatch"};
    reset_state();
    assert(run(1, plain) == 2);
    init_result = 0;
    assert(setenv("IPAKEEP_KSLIDE", "0x1000", 1) == 0);
    assert(run(1, plain) == 0);
    assert(write_count == 0);
    char *unknown[] = {"lvpatch", "--unknown"};
    assert(run(2, unknown) == 2);
    char *unexpected[] = {"lvpatch"};
    instruction = 0xfeed;
    assert(run(1, unexpected) == 1);
    unsetenv("IPAKEEP_KSLIDE");
}

static void test_patch_restore_and_write_failure(void) {
    char *patch[] = {"lvpatch", "--patch"};
    char *restore[] = {"lvpatch", "--restore"};
    reset_state();
    assert(setenv("IPAKEEP_KSLIDE", "0x1000", 1) == 0);
    assert(run(2, patch) == 0);
    assert(instruction == INSN_MOV_W0_0);
    assert(written_instruction == INSN_MOV_W0_0);
    assert(run(2, patch) == 0);
    assert(write_count == 1);
    assert(run(2, restore) == 0);
    assert(instruction == INSN_MOV_W0_1);
    instruction = 0xfeed;
    assert(run(2, patch) == 2);
    instruction = INSN_MOV_W0_1;
    write_sticks = 0;
    assert(run(2, patch) == 1);
    assert(write_count == 3);
    unsetenv("IPAKEEP_KSLIDE");
}

static void test_initialization_and_slide_failures(void) {
    char *plain[] = {"lvpatch"};
    reset_state();
    init_result = -1;
    assert(run(1, plain) == 2);
    reset_state();
    info_description = "no kernel information";
    has_info = 1;
    assert(run(1, plain) == 2);
    reset_state();
    assert(setenv("IPAKEEP_KSLIDE", "invalid", 1) == 0);
    assert(run(1, plain) == 2);
    unsetenv("IPAKEEP_KSLIDE");
}

int main(void) {
    test_slide_parsing();
    test_read_only_and_argument_errors();
    test_patch_restore_and_write_failure();
    test_initialization_and_slide_failures();
    return 0;
}
