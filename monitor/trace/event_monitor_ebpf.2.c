#include <uapi/linux/un.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>

#define MAX_PERCPU_BUFSIZE  (1 << 15)
#define MAX_STRING_SIZE     4096
#define MAX_STR_ARR_ELEM    20
#define MAX_PATH_PREF_SIZE  64

#define SUBMIT_BUF_IDX      0
#define STRING_BUF_IDX      1
#define FILE_BUF_IDX        2
#define MAX_BUFFERS         3

#define NONE_T        0UL
#define INT_T         1UL
#define UINT_T        2UL
#define LONG_T        3UL
#define ULONG_T       4UL
#define OFF_T_T       5UL
#define MODE_T_T      6UL
#define DEV_T_T       7UL
#define SIZE_T_T      8UL
#define POINTER_T     9UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define EXEC_FLAGS_T  14UL
#define SYSCALL_T     18UL
#define TYPE_MAX      255UL

#define SYS_EXECVE          59
#define SYS_EXECVEAT        322

/*== INTERNAL STRUCTS ==*/

typedef struct context {
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 eventid;
    u8 argnum;
    s64 retval;
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/*== MAPS ==*/

// BPF_HASH(pids_map, u32, u32);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);


/*== EVENTS ==*/

BPF_PERF_OUTPUT(events);

/*== HELPER FUNCTIONS ==*/

static u32 get_task_pid_ns_id(struct task_struct *task)
{
    return task->nsproxy->pid_ns_for_children->ns.inum;
}

static u32 get_task_ns_pid(struct task_struct *task)
{
    return task->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
}

static u32 get_task_ns_tgid(struct task_struct *task)
{
    return task->group_leader->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
}

static u32 get_task_ns_ppid(struct task_struct *task)
{
    return task->real_parent->thread_pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
}



static int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    return 0;
}

static buf_t* get_buf(int idx)
{
    return bufs.lookup(&idx);
}

static void set_buf_off(int buf_idx, u32 new_off)
{
    bufs_off.update(&buf_idx, &new_off);
}

static u32* get_buf_off(int buf_idx)
{
    return bufs_off.lookup(&buf_idx);
}

static int save_context_to_buf(buf_t *submit_p, void *ptr)
{
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static int save_to_submit_buf(buf_t *submit_p, void *ptr, int size, u8 type)
{
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        return 0;

    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        return 0;

    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        set_buf_off(SUBMIT_BUF_IDX, *off);
        return size;
    }

    return 0;
}

static int save_str_to_buf(buf_t *submit_p, void *ptr)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            return 0;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        set_buf_off(SUBMIT_BUF_IDX, *off);
        return sz + sizeof(int);
    }

    return 0;
}

static int events_perf_submit(struct pt_regs *ctx)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    int size = *off & (MAX_PERCPU_BUFSIZE-1);
    void * data = submit_p->buf;
    return events.perf_submit(ctx, data, size);
}

static int save_argv(buf_t *submit_p, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return save_str_to_buf(submit_p, (void *)(argp));
    }
    return 0;
}

static int save_str_arr_to_buf(buf_t *submit_p, const char __user *const __user *ptr)
{
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        if (save_argv(submit_p, (void *)&ptr[i]) == 0)
             goto out;
    }
    char ellipsis[] = "...";
    save_str_to_buf(submit_p, (void *)ellipsis);
out:
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    return 0;
}

#define DEC_ARG_TYPE(n, enc_type) ((enc_type>>(8*n))&0xFF)

static int save_args_to_submit_buf(u64 types, args_t *args)
{
    unsigned int i;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    for(i=0; i<6; i++)
    {
        switch (DEC_ARG_TYPE(i, types))
        {
            case NONE_T:
                break;
            case INT_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), INT_T);
                break;
            case UINT_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(unsigned int), UINT_T);
                break;
            case LONG_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(long), LONG_T);
                break;
            case ULONG_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(unsigned long), ULONG_T);
                break;
            case SIZE_T_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(size_t), SIZE_T_T);
                break;
            case POINTER_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(void*), POINTER_T);
                break;
            case STR_T:
                save_str_to_buf(submit_p, (void *)args->args[i]);
                break;
        }
    }

    return 0;
}

/*== SYSCALL HOOKS ==*/

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pns = (struct pid_namespace *) task->nsproxy->pid_ns_for_children;

    if (pns->ns.inum == PROC_PID_INIT_INO) {
        return 0;
    }

    context_t context = {};

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 2;
    // context.argnum = 3;
    context.retval = 0;
    save_context_to_buf(submit_p, (void*)&context);

    save_str_to_buf(submit_p, (void *)filename);
    save_str_arr_to_buf(submit_p, __argv);
    // save_str_arr_to_buf(submit_p, __envp);

    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execve(struct pt_regs *ctx)
{
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pns = (struct pid_namespace *) task->nsproxy->pid_ns_for_children;

    if (pns->ns.inum == PROC_PID_INIT_INO) {
        return 0;
    }

    context_t context = {};

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

int syscall__execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pns = (struct pid_namespace *) task->nsproxy->pid_ns_for_children;

    if (pns->ns.inum == PROC_PID_INIT_INO) {
        return 0;
    }

    context_t context = {};

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;



    context.eventid = SYS_EXECVEAT;
    // context.argnum = 5;
    context.argnum = 4;
    context.retval = 0;
    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&dirfd, sizeof(int), INT_T);
    save_str_to_buf(submit_p, (void *)pathname);
    save_str_arr_to_buf(submit_p, __argv);
    // save_str_arr_to_buf(submit_p, __envp);
    save_to_submit_buf(submit_p, (void*)&flags, sizeof(int), EXEC_FLAGS_T);

    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execveat(struct pt_regs *ctx)
{
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pns = (struct pid_namespace *) task->nsproxy->pid_ns_for_children;

    if (pns->ns.inum == PROC_PID_INIT_INO) {
        return 0;
    }

    context_t context = {};

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}
