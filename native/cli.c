#include <stdio.h>

#include "probe.h"

int main(void) {
    char report[SUCRUNE_PROBE_REPORT_CAPACITY];
    int result = sucrune_probe_run(report, sizeof(report));
    puts(report);
    return result;
}
