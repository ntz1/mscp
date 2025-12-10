/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/times.h>
#include <utime.h>

#include <fileops.h>
#include <ssh.h>
#include <print.h>
#include <platform.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h> // For _findfirst, etc., often used in MinGW
#include <limits.h>
#ifndef lstat
#define lstat stat
#endif
#endif

sftp_session __thread tls_sftp;
/* tls_sftp is used *_wrapped() functions */

void set_tls_sftp_session(sftp_session sftp)
{
	tls_sftp = sftp;
}

static void sftp_err_to_errno(sftp_session sftp)
{
	int sftperr = sftp_get_error(sftp);

	switch (sftperr) {
	case SSH_FX_OK:
	case SSH_FX_EOF:
		errno = 0;
		break;
	case SSH_FX_NO_SUCH_FILE:
	case SSH_FX_NO_SUCH_PATH:
		errno = ENOENT;
		break;
	case SSH_FX_PERMISSION_DENIED:
		errno = EACCES;
		break;
	case SSH_FX_FAILURE:
		errno = EINVAL;
	case SSH_FX_BAD_MESSAGE:
		errno = EBADMSG;
	case SSH_FX_NO_CONNECTION:
		errno = ENOTCONN;
		break;
	case SSH_FX_CONNECTION_LOST:
		errno = ENETRESET;
		break;
	case SSH_FX_OP_UNSUPPORTED:
		errno = EOPNOTSUPP;
		break;
	case SSH_FX_INVALID_HANDLE:
		errno = EBADF;
		break;
	case SSH_FX_FILE_ALREADY_EXISTS:
		errno = EEXIST;
		break;
	case SSH_FX_WRITE_PROTECT:
		errno = EPERM;
		break;
	case SSH_FX_NO_MEDIA:
		errno = ENODEV;
		break;
	default:
		pr_warn("unkown SSH_FX response %d", sftperr);
	}
}

MDIR *mscp_opendir(const char *path, sftp_session sftp)
{
	MDIR *md;

	if (!(md = malloc(sizeof(*md))))
		return NULL;
	memset(md, 0, sizeof(*md));

	if (sftp) {
		md->remote = sftp_opendir(sftp, path);
		sftp_err_to_errno(sftp);
		if (!md->remote) {
			goto free_out;
		}
	} else {
		md->local = opendir(path);
		if (!md->local) {
			goto free_out;
		}
	}

	return md;

free_out:
	free(md);
	return NULL;
}

MDIR *mscp_opendir_wrapped(const char *path)
{
	return mscp_opendir(path, tls_sftp);
}

void mscp_closedir(MDIR *md)
{
	if (md->remote)
		sftp_closedir(md->remote);
	else
		closedir(md->local);

	free(md);
}

struct dirent __thread tls_dirent;
/* tls_dirent contains dirent converted from sftp_attributes returned
 * from sftp_readdir(). This trick is derived from openssh's
 * fudge_readdir() */

struct dirent *mscp_readdir(MDIR *md)
{
	sftp_attributes attr;
	struct dirent *ret = NULL;
	static int inum = 1;

	if (md->remote) {
		attr = sftp_readdir(md->remote->sftp, md->remote);
		if (!attr) {
			sftp_err_to_errno(md->remote->sftp);
			return NULL;
		}

		memset(&tls_dirent, 0, sizeof(tls_dirent));
		strncpy(tls_dirent.d_name, attr->name, sizeof(tls_dirent.d_name) - 1);
		tls_dirent.d_ino = inum++;
		if (!inum)
			inum = 1;
		ret = &tls_dirent;
		sftp_attributes_free(attr);
	} else
		ret = readdir(md->local);

	return ret;
}

int mscp_mkdir(const char *path, mode_t mode, sftp_session sftp)
{
	int ret;

	if (sftp) {
		ret = sftp_mkdir(sftp, path, mode);
		sftp_err_to_errno(sftp);
	} else
#if defined(_WIN32)
		// On Windows/MinGW, the mode argument is often ignored or
		// the function only takes one argument. We drop the 'mode' argument here.
		ret = mkdir(path); 
#else
		// On POSIX systems (Linux, macOS, etc.), use the two-argument version.
		ret = mkdir(path, mode);
#endif

	if (ret < 0 && errno == EEXIST) {
		ret = 0;
	}

	return ret;
}

static void sftp_attr_to_stat(sftp_attributes attr, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_size = attr->size;
	st->st_uid = attr->uid;
	st->st_gid = attr->gid;
	st->st_mode = attr->permissions;

#if defined(__APPLE__) || defined(__FreeBSD__)
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif

#if defined(_WIN32)
	// MinGW/Windows uses direct time_t members
	st->st_atime = attr->atime;
	st->st_mtime = attr->mtime;
	st->st_ctime = attr->createtime;
#else
	// POSIX standard (Linux, macOS/BSD) uses timespec members
	st->st_atim.tv_sec = attr->atime;
	st->st_atim.tv_nsec = attr->atime_nseconds;
	st->st_mtim.tv_sec = attr->mtime;
	st->st_mtim.tv_nsec = attr->mtime_nseconds;
	st->st_ctim.tv_sec = attr->createtime;
	st->st_ctim.tv_nsec = attr->createtime_nseconds;
#endif

	switch (attr->type) {
	case SSH_FILEXFER_TYPE_REGULAR:
		st->st_mode |= S_IFREG;
		break;
	case SSH_FILEXFER_TYPE_DIRECTORY:
		st->st_mode |= S_IFDIR;
		break;
	case SSH_FILEXFER_TYPE_SYMLINK:
		st->st_mode |= S_IFLNK;
		break;
	case SSH_FILEXFER_TYPE_SPECIAL:
		st->st_mode |= S_IFCHR; /* or block? */
		break;
	case SSH_FILEXFER_TYPE_UNKNOWN:
		st->st_mode |= S_IFIFO; /* really? */
		break;
	default:
		pr_warn("unkown SSH_FILEXFER_TYPE %d", attr->type);
	}
}

int mscp_stat(const char *path, struct stat *st, sftp_session sftp)
{
	sftp_attributes attr;
	int ret = 0;

	memset(st, 0, sizeof(*st));

	if (sftp) {
		attr = sftp_stat(sftp, path);
		sftp_err_to_errno(sftp);
		if (!attr)
			return -1;

		sftp_attr_to_stat(attr, st);
		sftp_attributes_free(attr);
		ret = 0;
	} else
		ret = stat(path, st);

	return ret;
}

int mscp_stat_wrapped(const char *path, struct stat *st)
{
	return mscp_stat(path, st, tls_sftp);
}

int mscp_lstat(const char *path, struct stat *st, sftp_session sftp)
{
	sftp_attributes attr;
	int ret = 0;

	if (sftp) {
		attr = sftp_lstat(sftp, path);
		sftp_err_to_errno(sftp);
		if (!attr)
			return -1;

		sftp_attr_to_stat(attr, st);
		sftp_attributes_free(attr);
		ret = 0;
	} else
		ret = lstat(path, st);

	return ret;
}

int mscp_lstat_wrapped(const char *path, struct stat *st)
{
	return mscp_lstat(path, st, tls_sftp);
}

mf *mscp_open(const char *path, int flags, mode_t mode, sftp_session sftp)
{
	mf *f;

	f = malloc(sizeof(*f));
	if (!f)
		return NULL;
	memset(f, 0, sizeof(*f));

	if (sftp) {
		f->remote = sftp_open(sftp, path, flags, mode);
		if (!f->remote) {
			sftp_err_to_errno(sftp);
			goto free_out;
		}
	} else {
		f->local = open(path, flags, mode);
		if (f->local < 0)
			goto free_out;
	}

	return f;

free_out:
	free(f);
	return NULL;
}

void mscp_close(mf *f)
{
	if (f->remote)
		sftp_close(f->remote);
	if (f->local > 0)
		close(f->local);
	free(f);
}

off_t mscp_lseek(mf *f, off_t off)
{
	off_t ret;

	if (f->remote) {
		ret = sftp_seek64(f->remote, off);
		sftp_err_to_errno(f->remote->sftp);
	} else
		ret = lseek(f->local, off, SEEK_SET);

	return ret;
}

int mscp_setstat(const char *path, struct stat *st, bool preserve_ts, sftp_session sftp)
{
	int ret;

	if (sftp) {
		struct sftp_attributes_struct attr;
		memset(&attr, 0, sizeof(attr));
		attr.permissions = st->st_mode;
		attr.size = st->st_size;
		attr.flags = (SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE);
		if (preserve_ts) {
#if defined(_WIN32)
			// Use MinGW/Windows time_t fields for SFTP attribute
			attr.atime = st->st_atime;
			attr.atime_nseconds = 0; // Windows stat generally lacks nanosecond precision
			attr.mtime = st->st_mtime;
			attr.mtime_nseconds = 0;
#else
			// Use POSIX timespec fields
			attr.atime = st->st_atim.tv_sec;
			attr.atime_nseconds = st->st_atim.tv_nsec;
			attr.mtime = st->st_mtim.tv_sec;
			attr.mtime_nseconds = st->st_mtim.tv_nsec;
#endif
			attr.flags |= (SSH_FILEXFER_ATTR_ACCESSTIME |
				       SSH_FILEXFER_ATTR_MODIFYTIME |
				       SSH_FILEXFER_ATTR_SUBSECOND_TIMES);
		}
		ret = sftp_setstat(sftp, path, &attr);
		sftp_err_to_errno(sftp);
	} else {
		if ((ret = truncate(path, st->st_size)) < 0)
			return ret;
		if (preserve_ts) {
#if defined(_WIN32)
			// Use the standard MinGW/Windows function for setting file times: utime
			struct utimbuf times;
			// Copy from MinGW's struct stat fields
			times.actime = st->st_atime; 
			times.modtime = st->st_mtime; 
			
			// utime is the compatible call for time_t values
			if ((ret = utime(path, &times)) < 0)
				return ret;
#else
			// POSIX standard setutimes (expects struct timespec via st_atim/st_mtim)
			if ((ret = setutimes(path, st->st_atim, st->st_mtim)) < 0)
				return ret;
#endif
		}
		// mscp_mkdir fix: already applied to remove 'mode' argument
		// ... assuming the mkdir fix from the previous turn is here:
		if ((ret = chmod(path, st->st_mode)) < 0)
			return ret;
	}

	return ret;
}

#if defined(_WIN32) && !defined(GLOB_ALTDIRFUNC)
/* Private function for Windows local globbing using FindFirstFile/FindNextFile */
static int mscp_glob_windows_local(const char *pattern, glob_t *pglob)
{
	WIN32_FIND_DATAA findData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	char **path_list = NULL;
	size_t path_count = 0;
	size_t max_paths = 16;
	
	// Initialize glob_t
	memset(pglob, 0, sizeof(*pglob));

	// Use FindFirstFileA (ANSI version)
	hFind = FindFirstFileA(pattern, &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		// ERROR_FILE_NOT_FOUND (2), ERROR_PATH_NOT_FOUND (3), ERROR_NO_MORE_FILES (18)
		if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND || err == ERROR_NO_MORE_FILES) {
			return GLOB_NOMATCH;
		}
		// Other serious error
		errno = EIO; 
		return GLOB_ABORTED;
	}

	path_list = calloc(max_paths, sizeof(char *));
	if (!path_list) {
		FindClose(hFind);
		return GLOB_NOSPACE;
	}
	
	// Extract the directory path from the pattern (e.g., "C:\path\*.txt" -> "C:\path")
	char dir_path_buf[MAX_PATH];
	const char *last_sep = strrchr(pattern, '/');
	if (!last_sep) last_sep = strrchr(pattern, '\\');
	
	size_t dir_len = 0;
	if (last_sep) {
		dir_len = last_sep - pattern;
		if (dir_len >= MAX_PATH) {
			dir_len = 0; // Fallback to current dir if path part is too long
		} else {
			strncpy(dir_path_buf, pattern, dir_len);
			dir_path_buf[dir_len] = '\0';
		}
	} else {
		// Pattern contains no path, e.g., "*.c"
		strcpy(dir_path_buf, ".");
	}

	do {
		// Skip "." and ".." unless they are the entire pattern
		if ((strcmp(findData.cFileName, ".") == 0) || (strcmp(findData.cFileName, "..") == 0)) {
			if (strcmp(pattern, ".") != 0 && strcmp(pattern, "..") != 0) {
				continue;
			}
		}
		
		// Reallocate if needed
		if (path_count >= max_paths) {
			max_paths *= 2;
			char **new_list = realloc(path_list, max_paths * sizeof(char *));
			if (!new_list) {
				// Clean up and return error
				for (size_t i = 0; i < path_count; i++) free(path_list[i]);
				free(path_list);
				FindClose(hFind);
				return GLOB_NOSPACE;
			}
			path_list = new_list;
		}

		// Construct the full path
		const char *filename = findData.cFileName;
		
		char *full_path;
		size_t path_len;
		
		if (dir_len > 0) {
			// dir_path_buf/filename
			const char *sep = (last_sep[0] == '/') ? "/" : "\\";
			path_len = dir_len + 1 + strlen(filename) + 1; // +1 for separator, +1 for null
			full_path = malloc(path_len);
			if (!full_path) { /* cleanup and return NOSPACE */ goto error_nospace; }
			snprintf(full_path, path_len, "%s%s%s", dir_path_buf, sep, filename);
		} else {
			// just the filename
			path_len = strlen(filename) + 1;
			full_path = strdup(filename);
			if (!full_path) { /* cleanup and return NOSPACE */ goto error_nospace; }
		}

		path_list[path_count++] = full_path;

	} while (FindNextFileA(hFind, &findData) != 0);

	FindClose(hFind);
	
	// Finalize the list
	pglob->gl_pathc = path_count;
	pglob->gl_pathv = path_list;
	// Mark it as our custom Windows glob for globfree to handle
	pglob->gl_offs = MSCP_GLOB_WINDOWS_FAKE; 
	
	// Return 0 on success, GLOB_NOMATCH if no paths were added
	return (path_count > 0) ? 0 : GLOB_NOMATCH;

error_nospace:
	for (size_t i = 0; i < path_count; i++) free(path_list[i]);
	free(path_list);
	FindClose(hFind);
	return GLOB_NOSPACE;
}
#endif // _WIN32 && !GLOB_ALTDIRFUNC

/* remote glob */
int mscp_glob(const char *pattern, int flags, glob_t *pglob, sftp_session sftp)
{
	int ret;
	
	if (sftp) {
		// --- SFTP/Remote Path (Uses GLOB_ALTDIRFUNC or the musl-like fallback) ---
#ifndef GLOB_ALTDIRFUNC
#define GLOB_NOALTDIRMAGIC INT_MAX
		/* musl does not implement GLOB_ALTDIRFUNC */
		pglob->gl_pathc = 1;
		pglob->gl_pathv = malloc(sizeof(char *));
		if (!pglob->gl_pathv) return GLOB_NOSPACE;
		pglob->gl_pathv[0] = strdup(pattern);
		if (!pglob->gl_pathv[0]) { free(pglob->gl_pathv); return GLOB_NOSPACE; }
		pglob->gl_offs = GLOB_NOALTDIRMAGIC;
		return 0;
#else
		flags |= GLOB_ALTDIRFUNC;
		set_tls_sftp_session(sftp);
		
		// The original logic with function pointers relies on the system glob() being present
		// and supporting GLOB_ALTDIRFUNC.
#if defined(__APPLE__) || defined(__FreeBSD__)
		pglob->gl_opendir = (void *(*)(const char *))mscp_opendir_wrapped;
		pglob->gl_readdir = (struct dirent * (*)(void *)) mscp_readdir;
		pglob->gl_closedir = (void (*)(void *))mscp_closedir;
		pglob->gl_lstat = mscp_lstat_wrapped;
		pglob->gl_stat = mscp_stat_wrapped;
#elif linux
		pglob->gl_opendir = (void *(*)(const char *))mscp_opendir_wrapped;
		pglob->gl_readdir = (void *(*)(void *))mscp_readdir;
		pglob->gl_closedir = (void (*)(void *))mscp_closedir;
		pglob->gl_lstat = (int (*)(const char *, void *))mscp_lstat_wrapped;
		pglob->gl_stat = (int (*)(const char *, void *))mscp_stat_wrapped;
#else
#error unsupported platform for GLOB_ALTDIRFUNC
#endif
#endif
	} 
	
#if defined(_WIN32) && !defined(GLOB_ALTDIRFUNC)
	if (!sftp) {
		// --- Windows Local Path (MinGW case) ---
		ret = mscp_glob_windows_local(pattern, pglob);
	} else {
		// If SFTP is active but GLOB_ALTDIRFUNC is missing (unlikely on Windows, 
		// but included for completeness if the user forces a build without libssh's GLOB_ALTDIRFUNC checks)
		// This path is usually covered by the GLOB_NOALTDIRMAGIC block above.
		ret = GLOB_NOSYS; 
	}
#else
	// --- POSIX Local Path or POSIX/SFTP with GLOB_ALTDIRFUNC ---
	ret = glob(pattern, flags, NULL, pglob);
#endif

	if (sftp)
		set_tls_sftp_session(NULL); // Cleanup only if sftp was active
		
	return ret;
}

void mscp_globfree(glob_t *pglob)
{
#if defined(_WIN32) && !defined(GLOB_ALTDIRFUNC)
	if (pglob->gl_offs == MSCP_GLOB_WINDOWS_FAKE) {
		// Custom cleanup for Windows fake glob
		for (size_t i = 0; i < pglob->gl_pathc; i++) {
			free(pglob->gl_pathv[i]);
		}
		free(pglob->gl_pathv);
		return;
	}
#endif
#ifndef GLOB_ALTDIRFUNC
	if (pglob->gl_offs == GLOB_NOALTDIRMAGIC) {
		free(pglob->gl_pathv[0]);
		free(pglob->gl_pathv);
		return;
	}
#endif
	
	// Fallback to standard globfree() for POSIX and GLOB_ALTDIRFUNC paths
#if !defined(_WIN32) || (defined(_WIN32) && defined(GLOB_ALTDIRFUNC))
	globfree(pglob);
#endif
}
