
#define pr_fmt(fmt) "hook_read: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>


int tamper_fd=-999;

MODULE_DESCRIPTION("read file");
MODULE_AUTHOR("oditynet <oditynet@gmail.com>");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#define USE_FENTRY_OFFSET 0

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define HIDDEN_USER "root"
static asmlinkage long (*real_sys_read)(struct pt_regs *regs);

static asmlinkage long fh_sys_read(struct pt_regs *regs)
{
/*
     * Pull the arguments we need out of the regs struct
     */
    int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;

    char *kbuf;
    //struct utmp *utmp_buf;
    long error;
    int i, ret;
    ret = real_sys_read(regs);
//pr_info("[*]\n");
    if ( tamper_fd == fd)
    {
	pr_info("[!] Modify\n");
	
	kbuf = kzalloc(count, GFP_KERNEL);
        if( kbuf == NULL)
            return ret;
        
	error = copy_from_user(kbuf, buf, ret);
        pr_info("%s %d\n", kbuf,ret);
        if (error != 0)
            return ret;

	for ( i = 0 ; i < ret ; i++ )
    	    kbuf[i]=0x00;
	if(ret > 5)
	{
    	    kbuf[0]=0x43;
    	    kbuf[0]=0x6f;
    	    kbuf[0]=0x6f;
    	    kbuf[0]=0x6c;
    	}
        error = copy_to_user(buf, kbuf, ret);
        kfree(kbuf);
        //return 4;
    }

    return ret;
}
#else
//static asmlinkage long (*real_sys_read)(unsigned long clone_flags,	unsigned long newsp, int __user *parent_tidptr,	int __user *child_tidptr, unsigned long tls);
static asmlinkage ssize_t (*real_sys_read)(int fildes, void *buf, size_t nbytes);
//static asmlinkage long fh_sys_read(unsigned long clone_flags,	unsigned long newsp, int __user *parent_tidptr,	int __user *child_tidptr, unsigned long tls)
static asmlinkage ssize_t fh_sys_read(int fildes, void *buf, size_t nbytes)
{
	long ret;

	pr_info("read() before\n");
	return 0;
	ret = real_sys_read(fildes,buf,nbytes);

	pr_info("read() after: %ld\n", ret);

	return ret;
}
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{

	long ret;
	char *kernel_filename;
	char *filename = (char *)regs->si;
	char *kbuf;
	long error;
	//char *target = "/etc/passwd";
	char *target = "/tmp/1.txt"; 
	//int target_len = 4;
	kbuf = kzalloc(NAME_MAX, GFP_KERNEL); 
        if(kbuf == NULL)
            return real_sys_openat(regs);
	//kernel_filename = duplicate_filename((void*) regs->di);
	error = copy_from_user(kbuf, filename, NAME_MAX);
        if(error)
            return real_sys_openat(regs);
        
        //if( memcmp(kbuf, target, target_len) == 0 )
        if (strstr(kbuf, target)!= NULL)
        {
	    tamper_fd = real_sys_openat(regs);
    	    pr_info("name: %s %d\n", kbuf,tamper_fd);
	    //tamper_fd = real_sys_openat(regs);
	    kfree(kbuf);
    	    return tamper_fd;
	}
	kfree(kbuf);
        return real_sys_openat(regs);
}
#else
//static asmlinkage long (*real_sys_openat)(const char __user *filename,	const char __user *const __user *argv,	const char __user *const __user *envp);
static asmlinkage long (*real_sys_openat)(const struct pt_regs *);
//static asmlinkage long fh_sys_openat(const char __user *filename,	const char __user *const __user *argv,	const char __user *const __user *envp)
static asmlinkage long (*fh_sys_openat)(const struct pt_regs *)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);

	pr_info("fh_sys_openat() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_openat(filename, argv, envp);

	pr_info("fh_sys_openat() after: %ld\n", ret);

	return ret;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	//HOOK("sys_clone",  fh_sys_read,  &real_sys_read),
	//HOOK("sys_execve", fh_sys_openat, &real_sys_openat),
	HOOK("sys_read",  fh_sys_read,  &real_sys_read),
	HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
