/* VulnForge 靶场样本 2 · 堆越界写（教学用，故意包含漏洞）
 *
 * 类型：堆缓冲区溢出（CWE-122）
 * 触发：输入长度 > 32 时向 32 字节堆块写入 size×8192 字节，越界量越过堆区
 *       初始映射触发 SIGSEGV。
 * 说明（实测教训）：
 *   1) 小越界量会被 glibc tcache 路径吞掉不报错；
 *   2) 拷贝后必须读回（sink），否则 clang -O1 会做死存储消除，把 memcpy 整段删除。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int vuln_entry(const uint8_t *data, size_t size) {
    char *buf = malloc(32);
    uint8_t sink;

    if (buf == NULL) {
        return 0;
    }
    if (size > 32) {
        memcpy(buf, data, size * 8192u); /* 运行时长度大越界写；读回防 DSE */
    } else {
        memcpy(buf, data, size);
    }
    sink = (uint8_t)buf[0];
    free(buf);
    return sink;
}
