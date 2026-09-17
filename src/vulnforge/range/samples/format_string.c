/* VulnForge 靶场样本 5 · 格式化字符串（教学用，故意包含漏洞）
 *
 * 类型：外部可控格式串（CWE-134）
 * 触发：输入含 %n / %s 等转换符时被 printf 解析为格式串（SIGSEGV / 任意写）。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int vuln_entry(const uint8_t *data, size_t size) {
    char buf[256];
    size_t n = size < 255 ? size : 255;

    memcpy(buf, data, n);
    buf[n] = '\0';
    printf(buf); /* 格式串来自输入 */
    return 0;
}
