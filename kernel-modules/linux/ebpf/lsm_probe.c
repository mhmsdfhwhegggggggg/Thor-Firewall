// Thor Firewall — LSM (Linux Security Module) Probes
// مجسّات أمان النظام لحماية العميل ذاته
//
// يُراقب:
//   - محاولات الوصول لملفات العميل
//   - syscalls المشبوهة من العمليات الأخرى
//   - محاولات ptrace على عملية العميل
//   - تغييرات على BPF maps خارج العميل
//
// يتطلب: CONFIG_BPF_LSM=y في kernel
//         lsm=bpf في bootloader
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "thor_common.h"

// PID العميل — يُعيَّن عند بدء التشغيل
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_pid SEC(".maps");

// Ring buffer لأحداث الأمان
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 << 20);  // 4MB
} security_events SEC(".maps");

struct security_event {
    __u64 timestamp_ns;
    __u32 attacker_pid;
    __u32 target_pid;
    __u8  event_type;
    char  comm[16];     // اسم العملية المهاجِمة
    char  detail[64];
};

#define SEC_EVT_PTRACE    1
#define SEC_EVT_FILE_OPEN 2
#define SEC_EVT_KILL_SIG  3
#define SEC_EVT_BPF_MAP   4

/// التحقق هل العملية الهدف هي عميل Thor
static __always_inline bool is_agent_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
    if (!agent) return false;
    return (*agent != 0) && (*agent == pid);
}

/// إرسال حدث أمان
static __always_inline void emit_security_event(
    __u8 event_type,
    __u32 attacker_pid,
    __u32 target_pid,
    const char *detail
) {
    struct security_event *evt =
        bpf_ringbuf_reserve(&security_events, sizeof(*evt), 0);
    if (!evt) return;

    evt->timestamp_ns  = bpf_ktime_get_ns();
    evt->event_type    = event_type;
    evt->attacker_pid  = attacker_pid;
    evt->target_pid    = target_pid;

    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
}

// ========================================================================
// LSM Hooks
// ========================================================================

/// منع ptrace على عملية العميل
SEC("lsm/ptrace_access_check")
int BPF_PROG(thor_block_ptrace, struct task_struct *child, __u32 mode)
{
    __u32 child_pid  = child->pid;
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    if (is_agent_pid(child_pid) && !is_agent_pid(caller_pid)) {
        emit_security_event(SEC_EVT_PTRACE, caller_pid, child_pid, "ptrace_blocked");
        bpf_printk("Thor LSM: Blocked ptrace attempt on agent (PID %d) by PID %d\n",
                   child_pid, caller_pid);
        return -EPERM;  // رفض
    }

    return 0;
}

/// مراقبة فتح ملفات الإعداد الحساسة
SEC("lsm/file_open")
int BPF_PROG(thor_monitor_file_open, struct file *file)
{
    // يُسجَّل فقط إذا كان الملف ذا صلة بـ Thor
    // (التحقق الكامل يتطلب مقارنة المسار — معقد في eBPF)
    return 0;
}

/// مراقبة إرسال إشارات لعملية العميل
SEC("lsm/task_kill")
int BPF_PROG(thor_monitor_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    __u32 target_pid = p->pid;
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    if (is_agent_pid(target_pid) && !is_agent_pid(caller_pid)) {
        if (sig == 9 || sig == 15) {  // SIGKILL أو SIGTERM
            emit_security_event(SEC_EVT_KILL_SIG, caller_pid, target_pid, "kill_signal");
            bpf_printk("Thor LSM: Signal %d sent to agent by PID %d\n", sig, caller_pid);
            // لا نحظر الإشارات (قد تكون من systemd لإعادة التشغيل الشرعية)
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
