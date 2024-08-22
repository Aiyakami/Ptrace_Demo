#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define SHELLCODE_SIZE 64

struct user_regs_struct regs, original_regs;
long ptrace_detach(pid_t target) {
    return ptrace(PTRACE_DETACH, target, NULL, NULL);
}
long ptrace_getregs(pid_t target, struct user_regs_struct *regs) {
    return ptrace(PTRACE_GETREGS, target, NULL, regs);
}

//通过 ptrace 机制向目标进程发起系统调用的操作
//将参数设置到目标进程的寄存器中，并执行指定的指令地址
long ptrace_call(pid_t target, uintptr_t addr, long *params, int num_params) {
    int i;
    for (i = 0; i < num_params && i < 6; i++) {
        regs.rdi = params[0];
        regs.rsi = params[1];
        regs.rdx = params[2];
        regs.rcx = params[3];
        regs.r8  = params[4];
        regs.r9  = params[5];
    }
    regs.rip = addr;
    regs.rax = 0;
    ptrace_setregs(target, &regs);
    ptrace(PTRACE_CONT, target, NULL, NULL);
    wait(NULL);

    ptrace_getregs(target, &regs);
    return regs.rax;
}
uintptr_t find_library_address(pid_t pid, const char *library) {
    char filename[32];
    char buffer[4096];
    FILE *fp;
    uintptr_t addr = 0;
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, library)) {
            addr = strtoull(buffer, NULL, 16);
            break;
        }
    }

    fclose(fp);
    return addr;
}
void inject_so(pid_t pid,const char *so_path){
    void *handle;
    uintptr_t dlopen_addr;
    uintptr_t libc_base=find_library_address(pid,"libc");
    if(!libc_base){
        fprintf(stderr,"Failed to find libc base address\n");
    }
    //dlsym第一个参数是模块名，第二个是函数名称
    //RTLD_NEXT 是 dlsym 函数的一个特殊标志，用于获取下一个匹配的符号（函数或变量）
    dlopen_addr =  libc_base + (uintptr_t)dlsym(RTLD_NEXT, "dlopen");
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace_attach");
        return;
    }
    wait(NULL);
    //通过ptrace调用获取寄存器值
    ptrace(PTRACE_GETREGS, pid, NULL, regs);
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));
    size_t len=strlen(so_path)+1;
    //开辟栈空间，栈空间的地址往低处增长，写入数据时，数据填充是往高处增长的
    uintptr_t code_addr = regs.rsp - len;
    code_addr&=~0xF;
    long params[]={code_addr,RTLD_NOW};
    ptrace(PTRACE_POKETEXT, pid, (void *)code_addr, (long)so_path);
    //调用dlopen函数，dlopen函数的参数为需要注入的so文件
    ptrace_call(pid,dlopen_addr,params,2);

    ptrace(PTRACE_SETREGS, pid, NULL, original_regs;
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
//argc:argument cout参数计数 argv:argument vector参数指针
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <PID> <path_to_so>\n", argv[0]);
        return -1;
    }
    pid_t target_pid = atoi(argv[1]);
    const char *so_path = argv[2];
    inject_so(target_pid, so_path);
    return 0;
}