// cmdlinehide — 把 /proc/cmdline 里的解锁痕迹等长替换成锁定状态
//
// 背景：CiAn 在用户态伪装了 ro.boot.* 属性，但 /proc/cmdline 是 bootloader
// 直接传给内核的启动参数，用户态改不了。检测方两边一读就发现矛盾：
//     ro.boot.verifiedbootstate = green      （属性，被我们改过）
//     oplusboot.verifiedbootstate=orange     （cmdline，bootloader 的原话）
// 正常设备这两个来源永远一致，不一致本身就是"有人动过属性"的证据。
//
// 做法：module_init 时通过 kallsyms 找到 saved_command_line，等长替换。
//
// 关键（v2 修复）：`saved_command_line` 的类型是 `char *`，所以
// kallsyms_lookup_name 返回的是「这个指针变量的地址」= char **，
// 必须解引用一次才是字符串。v1 直接把 char** 当 char* 用，
// strstr 在野指针上跑 → 内核 oops → 反复重启。
//
// v2 还加了三道保护，任何一道不过就安静退出，绝不冒险：
//   1. copy_from_kernel_nofault 读取符号内容（不会 oops）
//   2. 指针必须落在内核地址空间
//   3. nofault 预读 4 KB 验证那块内存确实可读
//
// 另外：kallsyms_lookup_name 从 5.7 起不再导出，地址由 insmod 参数传入
// （和 fgetpriority 的做法一致）。

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/uaccess.h>

#define PROBE_LEN 4096
#define KERNEL_BASE_MIN 0xffff000000000000UL

static char *kallsyms_fn;
module_param_named(kallsyms_lookup_name_fn, kallsyms_fn, charp, 0);
MODULE_PARM_DESC(kallsyms_lookup_name_fn, "address of kallsyms_lookup_name, in hex");

static unsigned long (*kln)(const char *name);

/* 等长替换：repl 比 needle 短就用空格补齐，长于 needle 时拒绝（不冒险） */
static int swap_inplace(char *base, const char *needle, const char *repl)
{
    char *p;
    size_t n = strlen(needle), r = strlen(repl);

    if (r > n)
        return -EINVAL;

    p = strstr(base, needle);
    if (!p)
        return -ENOENT;

    memcpy(p, repl, r);
    if (r < n)
        memset(p + r, ' ', n - r);

    pr_info("cmdlinehide: replaced '%s' -> '%s'\n", needle, repl);
    return 0;
}

static int __init ch_init(void)
{
    unsigned long addr, raw_ptr;
    unsigned long *sym;
    char *cmdline;
    static char probe[PROBE_LEN];

    if (!kallsyms_fn || !*kallsyms_fn) {
        pr_info("cmdlinehide: kallsyms_lookup_name_fn not given\n");
        return -EINVAL;
    }

    /* simple_strtoull 在 5.10+ 已移除，用 kstrtoul */
    if (kstrtoul(kallsyms_fn, 16, &addr) || !addr) {
        pr_info("cmdlinehide: bad kallsyms address '%s'\n", kallsyms_fn);
        return -EINVAL;
    }
    kln = (void *)addr;

    sym = (unsigned long *)kln("saved_command_line");
    if (!sym) {
        pr_info("cmdlinehide: saved_command_line not found\n");
        return -ENOENT;
    }

    /* saved_command_line 的类型是 char *，这里拿到的只是它的地址 */
    if (copy_from_kernel_nofault(&raw_ptr, sym, sizeof(raw_ptr)) < 0) {
        pr_info("cmdlinehide: cannot read saved_command_line symbol\n");
        return -EINVAL;
    }
    cmdline = (char *)raw_ptr;

    if (!cmdline || raw_ptr < KERNEL_BASE_MIN) {
        pr_info("cmdlinehide: saved_command_line points nowhere (0x%lx)\n", raw_ptr);
        return -EINVAL;
    }

    /* 预读一遍确认这块内存可读，读不到就退出，绝不去写 */
    if (copy_from_kernel_nofault(probe, cmdline, PROBE_LEN) < 0) {
        pr_info("cmdlinehide: cmdline buffer unreadable, skip\n");
        return -EINVAL;
    }
    probe[PROBE_LEN - 1] = '\0';

    if (!strstr(probe, "verifiedbootstate=") &&
        !strstr(probe, "device_state=") &&
        !strstr(probe, "flash.locked=")) {
        pr_info("cmdlinehide: no target strings in cmdline, nothing to do\n");
        return 0;
    }

    swap_inplace(cmdline, "verifiedbootstate=orange", "verifiedbootstate=green");
    swap_inplace(cmdline, "device_state=unlocked", "device_state=locked");
    swap_inplace(cmdline, "flash.locked=0", "flash.locked=1");

    return 0;
}

static void __exit ch_exit(void)
{
    /* saved_command_line 不还原：模块只在开机早期改一次，卸载时已无意义 */
    pr_info("cmdlinehide: unloaded (cmdline left as is)\n");
}

module_init(ch_init);
module_exit(ch_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hide unlocked state in /proc/cmdline (equal-length in-place swap)");
MODULE_AUTHOR("cian");
