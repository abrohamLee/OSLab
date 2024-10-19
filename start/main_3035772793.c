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
#define MONITOR_INTERVAL_MS 300 // Monitoring interval in milliseconds

// Define Global Variable, Additional Header, and Functions Here
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h> 
#include <time.h>    

int set_sched_policy(pid_t pid, int policy, int nice, int priority) {
    struct sched_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = policy;
    attr.sched_nice = nice;
    attr.sched_priority = priority;

    return syscall(SYS_sched_setattr, pid, &attr, 0);
}

// Structure to pass data to monitoring thread
typedef struct {
    pid_t pid;
    volatile sig_atomic_t *terminate;
} monitor_data_t;

// Function to parse /proc/<pid>/stat and extract required fields
int parse_proc_stat(pid_t pid, int *pid_out, char **tcomm, char *state, int *policy, int *nice, unsigned long *vsize, int *task_cpu, unsigned long *utime, unsigned long *stime) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen stat");
        return -1;
    }

    // The tcomm field can contain spaces and is enclosed in parentheses
    // So, we need to read until the closing parenthesis
    int scanned_pid;
    char comm_buffer[256];

    // Read pid
    if (fscanf(fp, "%d", &scanned_pid) != 1) {
        fclose(fp);
        return -1;
    }
    *pid_out = scanned_pid;

    // Read comm (which may contain spaces)
    if (fscanf(fp, " (%[^)])", comm_buffer) != 1) {
        fclose(fp);
        return -1;
    }
    *tcomm = strdup(comm_buffer);

    // Read the state
    if (fscanf(fp, " %c", state) != 1) {
        fclose(fp);
        free(*tcomm);
        return -1;
    }

    // Initialize variables to skip to required fields
    int i;
    for (i = 4; i <= 52; i++) { // 假设 'policy' 是第41个字段
        if (i == 4) { // ppid
            int ppid;
            if (fscanf(fp, " %d", &ppid) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 14) { // utime
            if (fscanf(fp, " %lu", utime) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 15) { // stime
            if (fscanf(fp, " %lu", stime) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 19) { // nice
            if (fscanf(fp, " %d", nice) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 23) { // vsize
            if (fscanf(fp, " %lu", vsize) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 39) { // task_cpu (processor)
            if (fscanf(fp, " %d", task_cpu) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else if (i == 41) { // policy
            if (fscanf(fp, " %d", policy) != 1) {
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
        else { // Skip other fields
            char skip_buffer[256];
            if (fscanf(fp, " %s", skip_buffer) != 1) {
                // Handle unexpected EOF or read error
                fclose(fp);
                free(*tcomm);
                return -1;
            }
        }
    }

    fclose(fp);
    return 0;
}

// Function to get scheduling policy name from common.h
extern const char* get_sched_name(int policy);

// Monitoring thread function
void* monitor_thread_func(void *arg) {
    monitor_data_t *data = (monitor_data_t *)arg;
    pid_t pid = data->pid;
    volatile sig_atomic_t *terminate = data->terminate;

    unsigned long last_utime = 0, last_stime = 0; //记录上一次的用户态和系统态的运行时间
    double cpu_usage = 0.0;

    while (!(*terminate)) { //terminate为1时，退出循环, 停止监控
        int current_pid;
        char *tcomm;
        char state;
        int policy;
        int nice;
        unsigned long vsize;
        int task_cpu;
        unsigned long utime;
        unsigned long stime;

        if (parse_proc_stat(pid, &current_pid, &tcomm, &state, &policy, &nice, &vsize, &task_cpu, &utime, &stime) == 0) {
            // Calculate CPU usage
            if (last_utime != 0 || last_stime != 0) {
                unsigned long delta_utime = utime - last_utime;
                unsigned long delta_stime = stime - last_stime;
                // CPU usage calculation as per assignment
                cpu_usage = ((double)(delta_utime + delta_stime)) / (MONITOR_INTERVAL_MS / 10.0) * 100.0;
            }
            last_utime = utime;
            last_stime = stime;

            // Get scheduling policy name from common.h
            const char* sched_name = get_sched_name(policy);

            // Print to stderr
            fprintf(stderr, "[pid] %d [tcomm] (%s) [state] %c [policy] %s [nice] %d [vsize] %lu [task_cpu] %d [utime] %lu [stime] %lu [cpu%%] %.2f%%\n",
                current_pid, tcomm, state, sched_name, nice, vsize, task_cpu, utime, stime, cpu_usage);
            fflush(stderr);

            free(tcomm);
        } else {
            // Failed to parse /proc/{pid}/stat, possibly the process has exited
            break;
        }

        // Sleep for MONITOR_INTERVAL_MS milliseconds
        struct timespec req;
        req.tv_sec = MONITOR_INTERVAL_MS / 1000;
        req.tv_nsec = (MONITOR_INTERVAL_MS % 1000) * 1000000L;
        nanosleep(&req, NULL);
    }

    return NULL;
}
   


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
        // Child process: inference.c

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
        execl("./inference", "inference", seed, (char *)NULL);

        // If execl returns, an error occurred
        perror("execl");
        exit(EXIT_FAILURE);
    }

    // Parent process: main.c

    // 关闭父进程的读端，因为父进程只需要写数据
    close(pipefd[READ_END]);

    // Set scheduling policy for child process before first generation
    // Example: Set to SCHED_RR with priority 20
    // You can modify policy and parameters as needed

    // Define desired scheduling policy and parameters
    int desired_policy = SCHED_OTHER; 
    int desired_nice = 2;          // Nice value
    int desired_priority = 0;     // Priority for Real time policy, 对normal policy无效

    if (set_sched_policy(child_pid, desired_policy, desired_nice, desired_priority) == -1) {
        perror("set_sched_policy");
        // Optionally handle error, e.g., continue with default scheduling
    }

    // Create monitoring thread
    pthread_t monitor_thread;
    monitor_data_t monitor_data;
    monitor_data.pid = child_pid;
    monitor_data.terminate = &prompt_done; // Using prompt_done as a termination flag

    if (pthread_create(&monitor_thread, NULL, monitor_thread_func, &monitor_data) != 0) {
        perror("pthread_create");
        // Optionally handle error, e.g., exit
    }
    // Your Code Ends Here


    // Inform the user
    printf("请输入最多 %d 个提示。每个提示占一行。输入完成后，按 Ctrl+D (Unix/Linux) 或 Ctrl+Z 然后回车 (Windows) 结束输入。\n", MAX_PROMPTS);

    char prompt_buffer[MAX_PROMPT_LENGTH];
    int num_prompt = 0;

    while (num_prompt < MAX_PROMPTS) {
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

    // Inform the monitoring thread to terminate
    // Here, we set prompt_done to 1 to signal the monitoring thread to exit
    prompt_done = 1; //why not set *terminate to 1?

    // Wait for the monitoring thread to finish
    pthread_join(monitor_thread, NULL);

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