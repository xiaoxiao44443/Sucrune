#include "network_probe.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 1; \
} } while (0)

int main(void) {
    static const unsigned char allowed[][16] = {
        {127, 0, 0, 1},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
    };
    unsigned checks = 0;
    for (size_t which = 0; which < sizeof(allowed) / sizeof(allowed[0]); which++) {
        size_t length = which == 0U ? 4U : 16U;
        CHECK(sucrune_network_probe_loopback_bytes(allowed[which], length) == 1); checks++;
        for (size_t byte = 0; byte < length; byte++) {
            for (unsigned value = 0; value <= 255U; value++) {
                if (value == allowed[which][byte]) continue;
                unsigned char changed[16];
                memcpy(changed, allowed[which], sizeof(changed));
                changed[byte] = (unsigned char)value;
                CHECK(sucrune_network_probe_loopback_bytes(changed, length) == 0); checks++;
            }
        }
        for (size_t length_to_try = 0; length_to_try <= 17U; length_to_try++) {
            if (length_to_try == length) continue;
            CHECK(sucrune_network_probe_loopback_bytes(allowed[which], length_to_try) == 0); checks++;
        }
    }
    unsigned char compatible[16] = {0};
    compatible[12] = 127; compatible[15] = 1;
    CHECK(sucrune_network_probe_loopback_bytes(compatible, sizeof(compatible)) == 0); checks++;
    CHECK(sucrune_network_probe_loopback_bytes(NULL, 0U) == 0); checks++;
    CHECK(sucrune_network_probe_loopback_bytes(NULL, 4U) == 0); checks++;
    CHECK(sucrune_network_probe_loopback_bytes(NULL, 16U) == 0); checks++;
    (void)printf("network loopback address checks passed: %u\n", checks);
    return 0;
}
