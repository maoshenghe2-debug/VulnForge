/* VulnForge 靶场样本 6 · 命令注入（教学用，故意包含漏洞）
 *
 * 类型：命令注入（CWE-78）+ 无界拼接（CWE-120）
 * 触发：静态规则应命中 VF-C-002（sprintf）/ VF-C-004（system）；
 *       fuzz 路径——输入长度 > ~43 时 sprintf 越界（SIGABRT）。
 * 说明：为控制 shell 生成开销，仅当首字节为 '!' 时才实际执行命令（注入面保留）。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vuln_entry(const uint8_t *data, size_t size) {
    char cmd[48];
    char text[256];
    size_t n = size < 255 ? size : 255;

    memcpy(text, data, n);
    text[n] = '\0';
    sprintf(cmd, "echo %s", text); /* 无界拼接 → 越界 */
    if (size > 0 && data[0] == '!') {
        system(cmd); /* 命令注入 */
    }
    return 0;
}
