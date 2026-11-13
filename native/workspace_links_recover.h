#ifndef SUCRUNE_WORKSPACE_LINKS_RECOVER_H
#define SUCRUNE_WORKSPACE_LINKS_RECOVER_H
#include <stdint.h>
#include <sys/stat.h>
/* The caller holds its exclusive per-environment namespace lock. */
int sucrune_links_recover(int rootfd, int storefd);
/* Verify that every name of a pinned inode is inside the private temporary directory.
 * The caller holds the environment namespace lock. A non-null marker selects emulated links. */
int sucrune_links_all_in_tmp(int root, const struct stat *file, const char *marker, uint64_t names);
int sucrune_links_all_beneath(int directory, const struct stat *file, const char *marker, uint64_t names);
#endif
