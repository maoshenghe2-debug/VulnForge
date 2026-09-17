/* VulnForge 靶场样本 4 · 整数溢出（教学用，故意包含漏洞）
 *
 * 类型：整数回绕导致堆越界写（CWE-190 → CWE-787）
 * 触发：前 4 字节 len=0xFFFFFFFD 时 alloc = len + 4 回绕为 1，通过检查后按 len
 *       拷贝（约 4 GiB），立即越出堆区映射触发 SIGSEGV。
 * 说明（实测教训）：16 位回绕版不崩溃（64 KiB 越界量落在堆初始映射内被吞掉）；
 *       拷贝后读回 sink 防 clang -O1 死存储消除。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int vuln_entry(const uint8_t *data, size_t size) {
    uint32_t len;
    uint32_t alloc;
    char *p;
    uint8_t sink;

    if (size < 4) {
        return 0;
    }
    len = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    alloc = len + 4; /* 整数回绕：0xFFFFFFFD + 4 → 1 */
    if (alloc > 4096) {
        return 0;
    }
    p = malloc(alloc);
    if (p == NULL) {
        return 0;
    }
    memcpy(p, data, len); /* 越界写：len ≈ 4 GiB，立即越出堆映射 */
    sink = (uint8_t)p[0]; /* 读回：防死存储消除 */
    free(p);
    return sink;
}
