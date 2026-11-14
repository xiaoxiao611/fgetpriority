// cmdlinehide — 把 /proc/cmdline 里的解锁痕迹等长替换成锁定状态
//
// 为什么需要它：CiAn 在用户态伪装了 ro.boot.* 属性，但 /proc/cmdline 是
// bootloader 直接传给内核的启动参数，用户态改不了。检测方两边一读就发现矛盾：
//     ro.boot.verifiedbootstate = green      （属性，被我们改过）
//     oplusboot.verifiedbootstate=orange     （cmdline，bootloader 的原话）
// 正常设备这两个来源永远一致，不一致本身就是"有人动过属性"的证据。
//
// 做法：module_init 时通过 kallsyms 找到 saved_command_line 那块字符串，
// 把里面的 orange 等长替换成 "green "（多一个空格，cmdline 用空格分隔，
// 不影响解析），不改变长度、不移动内存，风险最低。
//
// 注意：kallsyms_lookup_name 从 5.7 起不再导出，地址由 insmod 参数传入
// （和 fgetpriority 的做法一致）。

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/init.h>

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
    char *cmdline;

    if (!kallsyms_fn || !*kallsyms_fn) {
        pr_info("cmdlinehide: kallsyms_lookup_name_fn not given\n");
        return -EINVAL;
    }

    kln = (void *)simple_strtoull(kallsyms_fn, NULL, 16);
    if (!kln) {
        pr_info("cmdlinehide: bad kallsyms address\n");
        return -EINVAL;
    }

    cmdline = (char *)kln("saved_command_line");
    if (!cmdline) {
        pr_info("cmdlinehide: saved_command_line not found\n");
        return -ENOENT;
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
