#ifndef SUCRUNE_WORKSPACE_LINKS_RECOVER_H
#define SUCRUNE_WORKSPACE_LINKS_RECOVER_H
/* The caller holds its exclusive per-environment namespace lock. */
int sucrune_links_recover(int rootfd, int storefd);
#endif
