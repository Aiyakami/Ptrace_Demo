#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>


/*
Linux系统没有像window中有CreateRemoteThread 或 WriteProcessMemory 这样直接修改其他进程内存的 API
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
*/
int main(){
    pid_t target_pid;
    long new_value=100;
    long addr;
    int status;
    //输入目标进程的pid
    printf("Enter the target process PID: ");
    scanf("%d", &target_pid);
    //附加到目标进程
    if(ptrace(PTRACE_ATTACH,target_pid,NULL,NULL)==-1){
        perror("Failed to attach to the target process");
        return 1;
    }
    //等待目标进程停止（此处不是终止，而是暂停）
    /*
    使用 ptrace(PTRACE_ATTACH) 附加到目标进程时，目标进程会收到一个 SIGSTOP 信号，这会导致它暂停执行。
    这个暂停确保了在你对目标进程内存进行任何修改时，进程不会同时执行其他操作，从而避免竞争条件或数据不一致。
    */
    waitpid(target_pid,&status,0);
    //获取到要修改内存的地址
    printf("Enter the memory address of the target variable: ");
    scanf("%lx", &addr);
    //写入新值
    if(ptrace(PTRACE_POKEDATA,target_pid,(void*)addr,(void*)new_value)==-1){
        //错误时需要分离进程
        perror("Failed to modify target process memory");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
     printf("Successfully modified the target process memory.\n");
     ptrace(PTRACE_DETACH,target_pid,NULL,NULL);
     return 0;

}

