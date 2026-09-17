/* VulnForge 靶场样本 1 · 栈溢出（教学用，故意包含漏洞）
 *
 * 类型：栈缓冲区越界写（CWE-121）
 * 说明：vuln_entry 把任意长度的输入拷贝进 32 字节栈缓冲，无边界检查。
 *       输入长度 >= 33 时触发栈保护中断（SIGABRT），为 fuzz 冒烟样本。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <string.h>

int vuln_entry(const uint8_t *data, size_t size) {
    char buf[32];
    memcpy(buf, data, size);
    return buf[0];
}
