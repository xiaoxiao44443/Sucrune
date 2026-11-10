#ifndef SUCRUNE_WORKSPACE_LINKS_H
#define SUCRUNE_WORKSPACE_LINKS_H
#include <stddef.h>
#define SUCRUNE_INODE_MARKER_PREFIX "sucrune:inode:v1:"
#define SUCRUNE_BASE_MARKER_PREFIX "sucrune:base:v1:"
#include <sys/stat.h>
/* The caller holds a flock on an independently opened environment directory
 * description through each namespace transaction. The store is outside it. */
struct sucrune_workspace_links { int parent,store,base; char name[256]; };
int sucrune_links_init(struct sucrune_workspace_links *,int root,const char *workspace);
int sucrune_links_clone(struct sucrune_workspace_links *,const struct sucrune_workspace_links *);
void sucrune_links_destroy(struct sucrune_workspace_links *);
int sucrune_links_open(struct sucrune_workspace_links *,int parent,const char *name,int flags,mode_t mode,ino_t *base_ino);
int sucrune_base_promote(struct sucrune_workspace_links *,int parent,const char *name);
int sucrune_links_target_info(struct sucrune_workspace_links *,int owned_path_fd,ino_t *base_ino);
int sucrune_links_target(struct sucrune_workspace_links *,int owned_path_fd);
int sucrune_links_stat(struct sucrune_workspace_links *,struct stat *);
int sucrune_links_tmp_write(struct sucrune_workspace_links *,int root,const struct stat *,int native);
int sucrune_links_publish(struct sucrune_workspace_links *,int oldparent,const char *oldname,int pinned,
                          int newparent,const char *newname);
int sucrune_links_unlink(struct sucrune_workspace_links *,int parent,const char *name,int flags);
int sucrune_links_rename(struct sucrune_workspace_links *,int parent,const char *name,int other,const char *newname);
int sucrune_links_dirents(struct sucrune_workspace_links *,int directory,unsigned char *data,size_t length);
#endif
