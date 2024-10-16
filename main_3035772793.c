/*
* PLEASE WRITE DOWN FOLLOWING INFO BEFORE SUBMISSION
* FILE NAME: 
* NAME: 
* UID:  
* Development Platform: 
* Remark: (How much you implemented?)
* How to compile separately: (gcc -o main main_[UID].c)
*/

#include "common.h"  // common definitions

#include <stdio.h>   // for printf, fgets, scanf, perror
#include <stdlib.h>  // for exit() related
#include <unistd.h>  // for folk, exec...
#include <wait.h>    // for waitpid
#include <signal.h>  // for signal handlers and kill
#include <string.h>  // for string related 
#include <sched.h>   // for sched-related
#include <syscall.h> // for syscall interface

#define READ_END       0    // helper macro to make pipe end clear
#define WRITE_END      1    // helper macro to make pipe end clear
#define SYSCALL_FLAG   0    // flags used in syscall, set it to default 0
#define MAX_PROMPT_LENGTH 1024 // Maximum length for a prompt
#define MAX_PROMPTS 4           // Maximum number of prompts

// Define Global Variable, Additional Header, and Functions Here
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

pid_t child_pid = -1;
volatile sig_atomic_t prompt_done = 0; //此信号指示prompt generation 是否完成(0为未完成， 1为已经完成)

void handle_sigusr1(int signum){ // 用于处理inference.c 发出的sigusr1信号，指示prompt generation是否完成
    prompt_done =1;
}
void handle_sigint(int signum){ //处理 SIGINT 信号，确保当主进程接收到 SIGINT（如用户按下 Ctrl+C）时，能够正确终止主进程&子进程(inference.c)并退出
    if (child_pid > 0){
        kill(child_pid, SIGINT); //向子进程发送 SIGINT 信号，通知它中断执行,kill调用成功时返回0,失败时返回-1
    }
    printf("\n主进程收到SIGINT信号，正在终止...\n");
    exit(EXIT_FAILURE); //当主进程接收到 SIGINT 信号时，首先向子进程发送 SIGINT 信号，要求子进程中断执行，之后主进程自己也会调用 exit(EXIT_FAILURE) 退出。
}


int main(int argc, char *argv[]) {
    char* seed; // 
    if (argc == 2) {
        seed = argv[1];
    } else if (argc == 1) {
        // use 42, the answer to life the universe and everything, as default
        seed = "42";
    } else {
        fprintf(stderr, "Usage: ./main <seed>\n");
        fprintf(stderr, "Note:  default seed is 42\n");
        exit(1);
    }

    // Write your main logic here
    
    // set signal handler
    struct sigaction sa_usr1; //sigaction 能实现比signal(SIGINT, handle_sigint); 更复杂的功能
    memset(&sa_usr1, 0, sizeof(sa_usr1));
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask); //sa_mask 用于指定那些在信号处理程序执行时应该被阻塞的信号
                                   //这里把它置为空，表示在处理SIGUSR1的时候不会阻塞其他任何信号
    sa_usr1.sa_flags = 0;          //表示使用默认的信号处理行为
    if(sigaction(SIGUSR1, &sa_usr1, NULL) == -1){ //绑定信号SIGUSR1和信号处理函数sa_usr1
        perror("sigaction SIGUSR1 failed");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa_int;
    memset(&sa_int, 0, sizeof(sa_int));
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if(sigaction(SIGINT, &sa_int, NULL) == -1){
        perror("sigaction SIGINT failed");
        exit(EXIT_FAILURE);
    }

    //create a pipeline for main and inference process
    int pipefd[2]; //pipe() 会创建一个管道然后返回2个文件描述符，pipefd[0]为读数据文件描述符, pipefd[1]为写数据文件描述符
    if(pipe(pipefd) == -1){
        perror("pipe failed");
        exit(EXIT_FAILURE);
    }

    child_pid = fork();
    if(child_pid == -1){
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // Child process: inference_UID.c

        // 关闭子进程的写段，因为子进程只需要读数据
        close(pipefd[WRITE_END]);

        // Redirect the read end of the pipe to stdin
        if (dup2(pipefd[READ_END], STDIN_FILENO) == -1) {
            perror("dup2");
            exit(EXIT_FAILURE);
        }

        // Close the original read end after duplicating
        close(pipefd[READ_END]);

        // Execute the inference process
        // Replace "./inference_UID" with the actual path to your inference executable
        execl("./inference", "inference", seed, (char *)NULL);

        // If execl returns, an error occurred
        perror("execl");
        exit(EXIT_FAILURE);
    }

    // Parent process: main_UID.c

    // 关闭父进程的读端，因为父进程只需要写数据
    close(pipefd[READ_END]);

    // Inform the user
    printf("请输入最多 %d 个提示。每个提示占一行。输入完成后，按 Ctrl+D (Unix/Linux) 或 Ctrl+Z 然后回车 (Windows) 结束输入。\n", MAX_PROMPTS);

    char prompt_buffer[MAX_PROMPT_LENGTH];
    int num_prompt = 0;

    while (num_prompt < MAX_PROMPTS) {
        // Print the prompt indicator
        printf(">>> ");
        fflush(stdout); // Ensure ">>> " is printed immediately

        // Read user input
        if (fgets(prompt_buffer, sizeof(prompt_buffer), stdin) == NULL) {
            // Check if EOF is reached
            if (feof(stdin)) {
                break; // Exit the loop if no more input
            } else {
                perror("fgets");
                break;
            }
        }

        // Remove trailing newline character, if any
        size_t len = strlen(prompt_buffer);
        if (len > 0 && prompt_buffer[len - 1] == '\n') {
            prompt_buffer[len - 1] = '\0';
        }

        if (strlen(prompt_buffer) == 0) {
            // Skip empty prompts
            continue;
        }

        // Write the prompt to the pipe, followed by a newline
        ssize_t bytes_written = write(pipefd[WRITE_END], prompt_buffer, strlen(prompt_buffer));
        if (bytes_written == -1) {
            perror("write to pipe");
            break;
        }

        bytes_written = write(pipefd[WRITE_END], "\n", 1);
        if (bytes_written == -1) {
            perror("write to pipe");
            break;
        }

        num_prompt++;

        // Wait for signal from inference process indicating prompt generation is done
        while (!prompt_done) {
            pause(); // Wait for signals
        }

        prompt_done = 0; // Reset the flag

        // Print the prompt indicator again to accept next input
        printf(">>> ");
        fflush(stdout);
    }

    // Close the write end of the pipe after sending all prompts
    close(pipefd[WRITE_END]);

    // Wait for the inference process to terminate
    int status;
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("waitpid");
        exit(EXIT_FAILURE);
    }

    // Print the exit status of the inference process
    if (WIFEXITED(status)) {
        printf("Child exited with %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Child was terminated by signal %d\n", WTERMSIG(status));
    } else {
        printf("Child ended abnormally\n");
    }

    // Your Code Ends Here

    return EXIT_SUCCESS;
}