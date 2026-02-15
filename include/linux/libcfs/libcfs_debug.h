/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Debug messages and assertions
 */

#ifndef __LIBCFS_DEBUG_H__
#define __LIBCFS_DEBUG_H__

#include <linux/tty.h>
#include <linux/limits.h>
#include <uapi/linux/lnet/libcfs_debug.h>

#ifdef CDEBUG_ENABLED

/*
 *  Debugging
 */
extern unsigned int libcfs_subsystem_debug;
extern unsigned int libcfs_debug;
extern unsigned int libcfs_subsystem_printk;
extern unsigned int libcfs_printk;
extern unsigned int libcfs_watchdog_ratelimit;
extern unsigned int libcfs_console_ratelimit;
extern unsigned int libcfs_console_max_delay;
extern unsigned int libcfs_console_min_delay;
extern unsigned int libcfs_console_backoff;
extern unsigned int libcfs_debug_binary;
extern char *libcfs_debug_file_path;

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 u64 *oldmask, u64 minmask, u64 allmask, u64 defmask);
int cfs_mask2str(char *str, int size, u64 mask, const char *(*bit2str)(int),
		 char sep);

int libcfs_debug_mask2str(char *str, int size, int mask, int is_subsys);
int libcfs_debug_str2mask(int *mask, const char *str, int is_subsys);

/* Has there been an LBUG? */
extern unsigned int libcfs_catastrophe;
extern unsigned int libcfs_panic_on_lbug;
extern bool libcfs_debug_raw_pointers;

int debug_format_buffer_alloc_buffers(void);
void debug_format_buffer_free_buffers(void);
bool get_debug_raw_pointers(void);
void set_debug_raw_pointers(bool value);

#else /* !CDEBUG_ENABLED */

#define libcfs_subsystem_debug	(~0U)
#define libcfs_debug		D_CANTMASK
#define libcfs_printk		D_CANTMASK
#define libcfs_subsystem_printk	(0U)
#define libcfs_watchdog_ratelimit (300U)
#define libcfs_console_ratelimit (1U)
#define libcfs_console_max_delay (0U)
#define libcfs_console_min_delay (0U)
#define libcfs_console_backoff	(2U)
#define libcfs_debug_binary	(0U)
#define libcfs_debug_file_path	"/tmp/lustre-log"
#define libcfs_catastrophe	(0U)
#define libcfs_panic_on_lbug	(1U)
#define libcfs_debug_raw_pointers (false)

static inline int debug_format_buffer_alloc_buffers(void) { return 0; }
static inline void debug_format_buffer_free_buffers(void) { }
static inline bool get_debug_raw_pointers(void) { return false; }
static inline void set_debug_raw_pointers(bool value) { }

#endif /* CDEBUG_ENABLED */

struct task_struct;

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

#define CDEBUG_DEFAULT_MAX_DELAY (cfs_time_seconds(600))         /* jiffies */
#define CDEBUG_DEFAULT_MIN_DELAY ((cfs_time_seconds(1) + 1) / 2) /* jiffies */
#define CDEBUG_DEFAULT_BACKOFF   2
struct cfs_debug_limit_state {
	unsigned long	cdls_next;
	unsigned int	cdls_delay;
	int		cdls_count;
};

struct libcfs_debug_msg_data {
	const char			*msg_file;
	const char			*msg_fn;
	int				 msg_subsys;
	int				 msg_line;
	int				 msg_mask;
	struct cfs_debug_limit_state	*msg_cdls;
};

#define LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line, msgdata, mask, cdls)\
do {									\
	(msgdata)->msg_subsys = DEBUG_SUBSYSTEM;			\
	(msgdata)->msg_file   = (file);					\
	(msgdata)->msg_fn     = (func);					\
	(msgdata)->msg_line   = (line);					\
	(msgdata)->msg_mask   = (mask);					\
	(msgdata)->msg_cdls   = (cdls);					\
} while (0)

#define LIBCFS_DEBUG_MSG_DATA_DECL_LOC(file, func, line, msgdata, mask, cdls)\
	static struct libcfs_debug_msg_data msgdata = {			\
		.msg_subsys = DEBUG_SUBSYSTEM,				\
		.msg_file   = (file),					\
		.msg_fn     = (func),					\
		.msg_line   = (line),					\
		.msg_cdls   = (cdls) };					\
	msgdata.msg_mask   = (mask)

#define LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, mask, cdls)			\
	LIBCFS_DEBUG_MSG_DATA_DECL_LOC(__FILE__, __func__, __LINE__,	\
				       msgdata, mask, cdls)

#ifdef CDEBUG_ENABLED

/**
 * Filters out logging messages based on mask and subsystem.
 */
static inline int cfs_cdebug_show(unsigned int mask, unsigned int subsystem)
{
	return mask & D_CANTMASK ||
	       ((libcfs_debug & mask) && (libcfs_subsystem_debug & subsystem));
}

#  define __CDEBUG_WITH_LOC(file, func, line, mask, cdls, format, ...)	\
do {									\
	static struct libcfs_debug_msg_data msgdata;			\
									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line,		\
					   &msgdata, mask, cdls);	\
		libcfs_debug_msg(&msgdata, format, ## __VA_ARGS__);	\
	}								\
} while (0)

#  define CDEBUG(mask, format, ...)					\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  mask, NULL, format, ## __VA_ARGS__)

#  define CDEBUG_LIMIT(mask, format, ...)				\
do {									\
	static struct cfs_debug_limit_state cdls;			\
									\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  mask, &cdls, format, ## __VA_ARGS__);		\
} while (0)

#  define CDEBUG_LIMIT_LOC(file, func, line, mask, format, ...)		\
do {									\
	static struct cfs_debug_limit_state cdls;			\
									\
	__CDEBUG_WITH_LOC(file, func, line,				\
			  mask, &cdls, format, ## __VA_ARGS__);		\
} while (0)

#  define CDEBUG_SLOW(delay, mask, format, ...)				\
do {									\
	static struct cfs_debug_limit_state cdls = {			\
	.cdls_count = -delay,						\
	.cdls_delay = delay,						\
	};								\
									\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  mask, &cdls, format, ## __VA_ARGS__);		\
} while (0)

void libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
		      const char *format1, ...)
	__printf(2, 3);

/* other external symbols that tracefile provides: */
int cfs_trace_copyout_string(char __user *usr_buffer, int usr_buffer_nob,
			     const char *knl_buffer, char *append);

# else /* !CDEBUG_ENABLED */

static inline int cfs_cdebug_show(unsigned int mask, unsigned int subsystem)
{
	return mask & D_CANTMASK;
}

#  define CDEBUG(mask, format, ...)					\
do {									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		LIBCFS_DEBUG_MSG_DATA_DECL(__msgdata, mask, NULL);	\
		libcfs_debug_msg(&__msgdata, format, ## __VA_ARGS__);	\
	}								\
} while (0)

#  define __CDEBUG_WITH_LOC(file, func, line, mask, cdls, format, ...)	\
do {									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		static struct libcfs_debug_msg_data __msgdata;		\
		LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line,		\
					   &__msgdata, mask, cdls);	\
		libcfs_debug_msg(&__msgdata, format, ## __VA_ARGS__);	\
	}								\
} while (0)

#  define CDEBUG_LIMIT(mask, format, ...)				\
do {									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		LIBCFS_DEBUG_MSG_DATA_DECL(__msgdata, mask, NULL);	\
		libcfs_debug_msg(&__msgdata, format, ## __VA_ARGS__);	\
	}								\
} while (0)

#  define CDEBUG_LIMIT_LOC(file, func, line, mask, format, ...)		\
	__CDEBUG_WITH_LOC(file, func, line, mask, NULL,			\
			  format, ## __VA_ARGS__)

#  define CDEBUG_SLOW(delay, mask, format, ...)				\
	CDEBUG_LIMIT(mask, format, ## __VA_ARGS__)

static inline void __printf(2, 3)
libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
		 const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	if (msgdata->msg_mask & D_EMERG)
		pr_emerg("LustreError: %pV", &vaf);
	else if (msgdata->msg_mask & D_ERROR)
		pr_err("LustreError: %pV", &vaf);
	else if (msgdata->msg_mask & D_WARNING)
		pr_warn("Lustre: %pV", &vaf);
	else
		pr_info("Lustre: %pV", &vaf);

	va_end(args);
}

static inline int cfs_trace_copyout_string(char __user *usr_buffer,
					   int usr_buffer_nob,
					   const char *knl_buffer,
					   char *append)
{
	int nob = strlen(knl_buffer);

	if (nob > usr_buffer_nob)
		nob = usr_buffer_nob;
	if (copy_to_user(usr_buffer, knl_buffer, nob))
		return -EFAULT;
	if (append != NULL && nob < usr_buffer_nob) {
		if (copy_to_user(usr_buffer + nob, append, 1))
			return -EFAULT;
		nob++;
	}
	return nob;
}

/* Mask/string conversion - static inline for header-only builds */
static inline int
cfs_mask2str(char *str, int size, u64 mask,
	     const char *(*bit2str)(int), char sep)
{
	const char *token;
	int len = 0;
	int i;

	if (mask == 0) {
		if (size > 0)
			str[0] = '0';
		len = 1;
	} else {
		for (i = 0; i < 64; i++) {
			if ((mask & BIT(i)) == 0)
				continue;
			token = bit2str(i);
			if (!token)
				continue;
			if (len > 0) {
				if (len < size)
					str[len] = sep;
				len++;
			}
			while (*token != 0) {
				if (len < size)
					str[len] = *token;
				token++;
				len++;
			}
		}
	}
	if (len < size)
		str[len++] = '\n';
	if (len < size)
		str[len] = '\0';
	else if (size)
		str[size - 1] = '\0';
	return len;
}

static inline int
cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
	     u64 *oldmask, u64 minmask, u64 allmask, u64 defmask)
{
	const char *debugstr;
	u64 newmask = *oldmask, found = 0;

	while (*str != 0) {
		int i, len;
		char op = 0;

		while (isspace(*str) || *str == ',')
			str++;
		if (*str == 0)
			break;
		if (*str == '+' || *str == '-') {
			op = *str++;
			while (isspace(*str))
				str++;
			if (*str == 0)
				return -EINVAL;
		} else if (!found)
			newmask = minmask;

		for (len = 0; str[len] != 0 && !isspace(str[len]) &&
		     str[len] != '+' && str[len] != '-' && str[len] != ',';
		     len++);

		found = 0;
		for (i = 0; i < 32; i++) {
			debugstr = bit2str(i);
			if (debugstr != NULL &&
			    strlen(debugstr) == len &&
			    strncasecmp(str, debugstr, len) == 0) {
				if (op == '-')
					newmask &= ~BIT(i);
				else
					newmask |= BIT(i);
				found = 1;
				break;
			}
		}
		if (!found && len == 3 &&
		    (strncasecmp(str, "ALL", len) == 0)) {
			if (op == '-')
				newmask = minmask;
			else
				newmask = allmask;
			found = 1;
		}
		if (!found && strcasecmp(str, "DEFAULT") == 0) {
			if (op == '-')
				newmask = (newmask & ~defmask) | minmask;
			else if (op == '+')
				newmask |= defmask;
			else
				newmask = defmask;
			found = 1;
		}
		if (!found)
			return -EINVAL;
		str += len;
	}
	*oldmask = newmask;
	return 0;
}

# endif /* CDEBUG_ENABLED */

/*
 * Lustre Error Checksum: calculates checksum
 * of Hex number by XORing each bit.
 */
#define LERRCHKSUM(hexnum) (((hexnum) & 0xf) ^ ((hexnum) >> 4 & 0xf) ^ \
			   ((hexnum) >> 8 & 0xf))

#define CWARN(format, ...)          CDEBUG_LIMIT(D_WARNING, format, ## __VA_ARGS__)
#define CERROR(format, ...)         CDEBUG_LIMIT(D_ERROR, format, ## __VA_ARGS__)
#define CNETERR(format, a...)       CDEBUG_LIMIT(D_NETERROR, format, ## a)
#define CEMERG(format, ...)         CDEBUG_LIMIT(D_EMERG, format, ## __VA_ARGS__)

#define CWARN_SLOW(delay, format, ...)  CDEBUG_SLOW(delay, D_WARNING, format, \
		   ## __VA_ARGS__)
#define CERROR_SLOW(delay, format, ...) CDEBUG_SLOW(delay, D_ERROR, format, \
		    ## __VA_ARGS__)

#define LCONSOLE(mask, format, ...) CDEBUG(D_CONSOLE | (mask), format, ## __VA_ARGS__)
#define LCONSOLE_INFO(format, ...)  CDEBUG_LIMIT(D_CONSOLE, format, ## __VA_ARGS__)
#define LCONSOLE_WARN(format, ...)  CDEBUG_LIMIT(D_CONSOLE | D_WARNING, format, ## __VA_ARGS__)
#define LCONSOLE_ERROR(format, ...) CDEBUG_LIMIT(D_CONSOLE | D_ERROR, format, ## __VA_ARGS__)
#define LCONSOLE_EMERG(format, ...) CDEBUG(D_CONSOLE | D_EMERG, format, ## __VA_ARGS__)

#define LIBCFS_DEBUG_FILE_PATH_DEFAULT "/tmp/lustre-log"

#if defined(CDEBUG_ENTRY_EXIT)

static inline long libcfs_log_return(struct libcfs_debug_msg_data *msgdata, long rc)
{
	libcfs_debug_msg(msgdata, "Process leaving (rc=%lu : %ld : %lx)\n",
			 rc, rc, rc);
	return rc;
}

static inline void libcfs_log_goto(struct libcfs_debug_msg_data *msgdata,
				   const char *label, long rc)
{
	libcfs_debug_msg(msgdata,
			 "Process leaving via %s (rc=%lu : %ld : %#lx)\n",
			 label, rc, rc, rc);
}

# define GOTO(label, rc)						      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		LIBCFS_DEBUG_MSG_DATA_DECL(_goto_data, D_TRACE, NULL);	      \
		libcfs_log_goto(&_goto_data, #label, (long)(rc));	      \
	} else {							      \
		(void)(rc);						      \
	}								      \
									      \
	goto label;							      \
} while (0)

# if BITS_PER_LONG > 32
#  define RETURN(rc)							      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_TRACE, NULL);	      \
		return (typeof(rc))libcfs_log_return(&msgdata,		      \
						     (long)(rc));	      \
	}								      \
									      \
	return rc;							      \
} while (0)
# else /* BITS_PER_LONG == 32 */
/* We need an on-stack variable, because we cannot case a 32-bit pointer
 * directly to (long long) without generating a complier warning/error, yet
 * casting directly to (long) will truncate 64-bit return values. The log
 * values will print as 32-bit values, but they always have been. LU-1436
 */
#  define RETURN(rc)							      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		typeof(rc) __rc = (rc);					      \
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_TRACE, NULL);	      \
		libcfs_log_return(&msgdata, (long)__rc);		      \
		return __rc;						      \
	}								      \
									      \
	return rc;							      \
} while (0)

# endif /* BITS_PER_LONG > 32 */

# define ENTRY	CDEBUG(D_TRACE, "Process entered\n")
# define EXIT	CDEBUG(D_TRACE, "Process leaving\n")

#else /* !CDEBUG_ENTRY_EXIT */

# define GOTO(label, rc)						\
	do {								\
		((void)(rc));						\
		goto label;						\
	} while (0)

# define RETURN(rc) return (rc)
# define ENTRY	do { } while (0)
# define EXIT	do { } while (0)

#endif /* CDEBUG_ENTRY_EXIT */

#define RETURN_EXIT							\
do {									\
	EXIT;								\
	return;								\
} while (0)

#define ENUM2STR(x) case x: return #x

static inline void cfs_tty_write_msg(const char *msg)
{
	struct tty_struct *tty;

	tty = get_current_tty();
	if (!tty)
		return;
	mutex_lock(&tty->atomic_write_lock);
	tty_lock(tty);
	if (tty->ops->write && tty->count > 0)
		tty->ops->write(tty, msg, strlen(msg));
	tty_unlock(tty);
	mutex_unlock(&tty->atomic_write_lock);
	wake_up_interruptible_poll(&tty->write_wait, POLL_OUT);
	tty_kref_put(tty);
}

#endif	/* __LIBCFS_DEBUG_H__ */
