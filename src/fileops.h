/* SPDX-License-Identifier: GPL-3.0-only */
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#include <ssh.h>

// --- Start of MinGW/Windows Compatibility Definitions ---
#if defined(_WIN32)

// POSIX glob error and status flags (missing in MinGW/Windows standard library)
#ifndef GLOB_NOSYS
// Glob function return codes
#define GLOB_ABORTED  1 // Read error
#define GLOB_NOMATCH  2 // No match
#define GLOB_NOSPACE  3 // Malloc failure
#define GLOB_NOSYS    5 // Function not supported

// Glob flags (used in function call)
#define GLOB_ERR      (1 << 0) // Stop on read error 
#define GLOB_MARK     (1 << 1) // Append a slash to directories
#define GLOB_NOSORT   (1 << 2) // Do not sort results
#define GLOB_DOOFFS   (1 << 3) // Add gl_offs to gl_pathv
#define GLOB_NOCHECK  (1 << 4) // Return pattern if no match
#define GLOB_APPEND   (1 << 5) // Append to results
#define GLOB_NOESCAPE (1 << 6) // Disable backslash quoting 
#define GLOB_PERIOD   (1 << 7) // Match starting with '.'
#define GLOB_ONLYDIR  (1 << 8) // Return only directories
#endif

// Define the custom tags used in fileops.c
#ifndef GLOB_ALTDIRFUNC
#define GLOB_NOALTDIRMAGIC INT_MAX
#endif
#define MSCP_GLOB_WINDOWS_FAKE 0x80000000 

// Define glob_t struct if the system header hasn't defined it
typedef struct {
	size_t gl_pathc;    /* Count of paths matched by pattern */
	char **gl_pathv;    /* List of matched pathnames */
	size_t gl_offs;     /* Slots before gl_pathv[0] (used for flags/magic) */
} glob_t;

// Fix for S_IFLNK being undeclared on MinGW/Windows
#ifndef S_IFLNK
#define S_IFLNK 0xA000 // POSIX standard value for Symbolic Link
#endif

#else
// --- POSIX/Default Case ---
#include <glob.h> 
#endif
// --- End of MinGW/Windows Compatibility Definitions ---

void set_tls_sftp_session(sftp_session sftp);
/* sftp_session set by set_tls_sftp_session is sued in
 mscp_open_wrapped(), mscp_stat_wrapped(), and
 mscp_lstat_wrapped(). This _wrapped() functions exist for
 sftp_glob() */

/* directory operations */

struct mdir_struct {
	DIR *local;
	sftp_dir remote;
};
typedef struct mdir_struct MDIR;

MDIR *mscp_opendir(const char *path, sftp_session sftp);
MDIR *mscp_opendir_wrapped(const char *path);
void mscp_closedir(MDIR *md);
struct dirent *mscp_readdir(MDIR *md);

int mscp_mkdir(const char *path, mode_t mode, sftp_session sftp);

/* stat operations */
int mscp_stat(const char *path, struct stat *st, sftp_session sftp);
int mscp_stat_wrapped(const char *path, struct stat *st);

int mscp_lstat(const char *path, struct stat *st, sftp_session sftp);
int mscp_lstat_wrapped(const char *path, struct stat *st);

/* file operations */

struct mf_struct {
	sftp_file remote;
	int local;
};
typedef struct mf_struct mf;

mf *mscp_open(const char *path, int flags, mode_t mode, sftp_session sftp);
void mscp_close(mf *f);
off_t mscp_lseek(mf *f, off_t off);

/* mscp_setstat() involves chmod and truncate. It executes both at
 * once via a single SFTP command (sftp_setstat()).
 */
int mscp_setstat(const char *path, struct stat *st, bool preserve_ts, sftp_session sftp);

/* remote glob */
int mscp_glob(const char *pattern, int flags, glob_t *pglob, sftp_session sftp);
void mscp_globfree(glob_t *pglob);
