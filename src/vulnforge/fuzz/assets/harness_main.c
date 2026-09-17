/* VulnForge 通用 fuzz harness（模板）
 *
 * 职责：读取输入（stdin 或 argv[1] 文件），调用目标提供的
 *       ``int vuln_entry(const uint8_t *data, size_t size)``。
 *
 * 用法：
 *   afl-fuzz ... -- ./target          （stdin 模式）
 *   afl-fuzz ... -- ./target @@       （文件模式，argv[1] 为输入文件）
 *
 * 目标源码需实现 vuln_entry；本文件由 build 流程自动附加编译。
 */
#include <stdint.h>
#include <stdio.h>

int vuln_entry(const uint8_t *data, size_t size);

#define VF_MAX_INPUT (1u << 20)

int main(int argc, char **argv) {
    static uint8_t buf[VF_MAX_INPUT];
    FILE *fp = stdin;
    size_t n;

    if (argc > 1) {
        fp = fopen(argv[1], "rb");
        if (!fp) {
            return 2;
        }
    }
    n = fread(buf, 1, VF_MAX_INPUT, fp);
    if (argc > 1) {
        fclose(fp);
    }
    if (n == 0) {
        return 0;
    }
    return vuln_entry(buf, n);
}
