/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

int cfs_arch_init(void);
void cfs_arch_exit(void);

int lustre_symbols_init(void);

#if !defined(CONFIG_SHRINKER_DEBUG)
void shrinker_debugfs_fini(void);
int shrinker_debugfs_init(void);
#else

static inline void shrinker_debugfs_fini(void) {};
static inline int shrinker_debugfs_init(void) { return 0; };
#endif
