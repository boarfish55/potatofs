/*
 *  Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
 *
 *  This file is part of PotatoFS, a FUSE filesystem implementation.
 *
 *  PotatoFS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "config.h"

struct fs_config fs_config = {
	DEFAULT_CONFIG_PATH,           /* config path */
	0,                             /* uid */
	0,                             /* gid */
	"",                            /* dbg */
	SLAB_MAX_OPEN_DEFAULT,         /* max_open_slabs */
	FS_DEFAULT_ENTRY_TIMEOUTS,     /* entry_timeouts */
	SLAB_MAX_AGE_DEFAULT,          /* slab_max_age */
	SLAB_SIZE_DEFAULT,             /* slab_size */
	FS_DEFAULT_DATA_PATH,          /* data_path */
	0,                             /* disable atime if 1 */
	MGR_DEFAULT_SOCKET_PATH,       /* manager socket path */
	MGR_DEFAULT_PIDFILE_PATH,      /* PID file path of manager */
	MGR_DEFAULT_BACKEND_EXEC,      /* manager backend executable */
	"",                            /* manager backend executable config */
	MGR_DEFAULT_UNPRIV_USER,       /* unpriv_user */
	MGR_DEFAULT_UNPRIV_GROUP,      /* unpriv_group */
	MGR_DEFAULT_WORKERS,           /* workers */
	MGR_DEFAULT_BGWORKERS,         /* bgworkers */
	MGR_DEFAULT_PURGER_INTERVAL,   /* purger_interval */
	MGR_DEFAULT_SCRUBBER_INTERVAL, /* scrubber_interval */
	MGR_DEFAULT_DF_INTERVAL,       /* df_interval */
	DEFAULT_UNCLAIM_PURGE_PCT,     /* unclaim_purge_threshold_pct */
	DEFAULT_PURGE_PCT,             /* purge_threshold_pct */
	DEFAULT_BACKEND_GET_TIMEOUT,   /* backend_get_timeout */
	DEFAULT_BACKEND_PUT_TIMEOUT,   /* backend_put_timeout */
	DEFAULT_BACKEND_DF_TIMEOUT,    /* backend_df_timeout */
	0                              /* shutdown_grace_period */
};

void
config_read()
{
	char         buf[PATH_MAX + 32];
	char        *line;
	int          line_n = 0;
	FILE        *cfg;

	const char *p, *v;

	if (access(fs_config.cfg_path, F_OK|R_OK) == -1)
		err(1, "%s", fs_config.cfg_path);
	if ((cfg = fopen(fs_config.cfg_path, "r")) == NULL)
		err(1, "%s", fs_config.cfg_path);

	while (fgets(buf, sizeof(buf), cfg)) {
		line_n++;
		line = buf;

		while (*line == ' ')
			line++;

		if (*line == '#' || *line == '\n' || *line == '\0')
			continue;

		p = strtok(line, ":");
		if (p == NULL) {
			warnx("invalid line in configuration: %d", line_n);
			continue;
		}

		v = strtok(NULL, "\n");
		if (v == NULL) {
			warnx("invalid line in configuration; no value: %d",
			    line_n);
			continue;
		}

		while (*v == ' ')
			v++;

		if (strcmp(p, "data_dir") == 0) {
			strlcpy(fs_config.data_dir, v,
			    sizeof(fs_config.data_dir));
		} else if (strcmp(p, "mgr_socket_path") == 0) {
			strlcpy(fs_config.mgr_sock_path, v,
			    sizeof(fs_config.mgr_sock_path));
		} else if (strcmp(p, "pidfile_path") == 0) {
			strlcpy(fs_config.pidfile_path, v,
			    sizeof(fs_config.pidfile_path));
		} else if (strcmp(p, "backend") == 0) {
			strlcpy(fs_config.mgr_exec, v,
			    sizeof(fs_config.mgr_exec));
		} else if (strcmp(p, "backend_config") == 0) {
			strlcpy(fs_config.mgr_exec_config, v,
			    sizeof(fs_config.mgr_exec_config));
		} else if (strcmp(p, "slab_size") == 0) {
			if ((fs_config.slab_size = strtoul(v, NULL, 10))
			    == ULONG_MAX)
				err(1, "slab_size");
		} else if (strcmp(p, "dbg") == 0) {
			strlcpy(fs_config.dbg, v,
			    sizeof(fs_config.dbg));
		} else if (strcmp(p, "noatime") == 0) {
			if (strcmp(v, "yes") == 0)
				fs_config.noatime = 1;
			else if (strcmp(v, "no") == 0)
				fs_config.noatime = 0;
			else
				warnx("noatime must be 'yes' or 'no'");
		} else if (strcmp(p, "slab_max_age") == 0) {
			if ((fs_config.slab_max_age =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "slab_max_age");
		} else if (strcmp(p, "unclaim_purge_threshold_pct") == 0) {
			if ((fs_config.unclaim_purge_threshold_pct =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "unclaim_purge_threshold_pct");
		} else if (strcmp(p, "purge_threshold_pct") == 0) {
			if ((fs_config.purge_threshold_pct =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "purge_threshold_pct");
		} else if (strcmp(p, "workers") == 0) {
			if ((fs_config.workers =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "workers");
		} else if (strcmp(p, "bgworkers") == 0) {
			if ((fs_config.bgworkers =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "bgworkers");
		} else if (strcmp(p, "purger_interval") == 0) {
			if ((fs_config.purger_interval =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "purger_interval");
		} else if (strcmp(p, "scrubber_interval") == 0) {
			if ((fs_config.scrubber_interval =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "scrubber_interval");
		} else if (strcmp(p, "df_interval") == 0) {
			if ((fs_config.df_interval =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "df_interval");
		} else if (strcmp(p, "max_open_slabs") == 0) {
			if ((fs_config.max_open_slabs =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "max_open_slabs");
		} else if (strcmp(p, "unpriv_user") == 0) {
			strlcpy(fs_config.unpriv_user, v,
			    sizeof(fs_config.unpriv_user));
		} else if (strcmp(p, "unpriv_group") == 0) {
			strlcpy(fs_config.unpriv_group, v,
			    sizeof(fs_config.unpriv_group));
		} else if (strcmp(p, "backend_get_timeout") == 0) {
			if ((fs_config.backend_get_timeout =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "backend_get_timeout");
		} else if (strcmp(p, "backend_put_timeout") == 0) {
			if ((fs_config.backend_put_timeout =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "backend_put_timeout");
		} else if (strcmp(p, "backend_df_timeout") == 0) {
			if ((fs_config.backend_df_timeout =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "backend_df_timeout");
		} else if (strcmp(p, "shutdown_grace_period") == 0) {
			if ((fs_config.shutdown_grace_period =
			    strtoul(v, NULL, 10)) == ULONG_MAX)
				err(1, "shutdown_grace_period");
		} else {
			warnx("unknown parameter: %s", p);
			continue;
		}
	}

	fclose(cfg);
}
