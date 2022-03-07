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
#include "config.h"

struct fs_config fs_config = {
	0,                           /* uid */
	0,                           /* gid */
	NULL,                        /* dbg */
	SLAB_MAX_OPEN_DEFAULT,       /* max_open_slabs */
	FS_DEFAULT_ENTRY_TIMEOUTS,   /* entry_timeouts */
	SLAB_MAX_AGE_DEFAULT,        /* slab_max_age */
	SLAB_SIZE_DEFAULT,           /* slab_size */
	FS_DEFAULT_DATA_PATH,        /* data_path */
	0,                           /* disable atime if 1 */
	MGR_DEFAULT_SOCKET_PATH,     /* manager socket path */
	MGR_DEFAULT_PIDFILE_PATH,    /* PID file path of manager */
	MGR_DEFAULT_BACKEND_EXEC,    /* manager backend executable */
	DEFAULT_CONFIG_PATH,         /* config path */
	DEFAULT_UNCLAIM_PURGE_PCT,   /* unclaim_purge_threshold_pct */
	DEFAULT_PURGE_PCT            /* purge_threshold_pct */
};

void
config_read()
{
	char         buf[PATH_MAX + 32];
	char        *line;
	int          line_n = 0;
	FILE        *cfg;

	const char *p, *v;

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
			fs_config.data_dir = strdup(v);
			if (fs_config.data_dir == NULL)
				err(1, "data_dir");
		} else if (strcmp(p, "mgr_socket_path") == 0) {
			fs_config.mgr_sock_path = strdup(v);
			if (fs_config.mgr_sock_path == NULL)
				err(1, "mgr_sock_path");
		} else if (strcmp(p, "pidfile_path") == 0) {
			fs_config.pidfile_path = strdup(v);
			if (fs_config.pidfile_path == NULL)
				err(1, "pidfile_path");
		} else if (strcmp(p, "backend") == 0) {
			fs_config.mgr_exec = strdup(v);
			if (fs_config.mgr_exec == NULL)
				err(1, "backend");
		} else if (strcmp(p, "slab_size") == 0) {
			if ((fs_config.slab_size = strtoul(v, NULL, 10))
			    == ULONG_MAX)
				err(1, "slab_size");
		} else if (strcmp(p, "dbg") == 0) {
			fs_config.dbg = strdup(v);
			if (fs_config.dbg == NULL)
				err(1, "dbg");
		} else if (strcmp(p, "noatime") == 0) {
			if (strcmp(v, "yes") == 0)
				fs_config.noatime = 1;
			else if (strcmp(v, "no") == 0)
				fs_config.noatime = 0;
			else
				warnx("noatime must be 'yes' or 'no'");
		} else if (strcmp(p, "slab_max_age") == 0) {
			if ((fs_config.slab_max_age =
			    strtol(v, NULL, 10)) == LONG_MAX)
				err(1, "slab_max_age");
		} else if (strcmp(p, "unclaim_purge_threshold_pct") == 0) {
			if ((fs_config.unclaim_purge_threshold_pct =
			    strtol(v, NULL, 10)) == LONG_MAX)
				err(1, "unclaim_purge_threshold_pct");
		} else if (strcmp(p, "purge_threshold_pct") == 0) {
			if ((fs_config.purge_threshold_pct =
			    strtol(v, NULL, 10)) == LONG_MAX)
				err(1, "purge_threshold_pct");
		} else {
			warnx("unknown parameter: %s", p);
			continue;
		}
	}

	fclose(cfg);
}
