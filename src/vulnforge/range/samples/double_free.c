/* VulnForge 靶场样本 3 · 双重释放（教学用，故意包含漏洞）
 *
 * 类型：双重释放（CWE-415，UAF 家族）
 * 触发：输入 ≥2 字节时二次 free，glibc tcache 检测中断（SIGABRT）。
 * 说明：以 volatile 间接引用绕开优化消除——实测 -O1 下直接写 free(p); free(p)
 *       会被 clang 优化掉不产生崩溃；完整 UAF（CWE-416）在无 ASan 时常不表现为
 *       崩溃，v0.2 将提供 ASan 模式。
 * 用途：仅用于自有环境的 fuzz 编排 / 崩溃分析教学与研究。
 */
#include <stdint.h>
#include <stdlib.h>

int vuln_entry(const uint8_t *data, size_t size) {
    char *p = malloc(64);
    void *volatile q;

    if (p == NULL) {
        return 0;
    }
    q = p;
    if (size > 0) {
        free(p);
    }
    if (size > 1) {
        free((void *)q); /* 双重释放（间接引用，防优化消除） */
    }
    return data[0];
}
