/*
 *  Copyright (C) 2020-2025 Pascal Lalonde <plalonde@overnet.ca>
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

#ifndef VERSION_H
#define VERSION_H

/*
 * Version loosely follows SemVer (semver.org). MAJOR must be updated
 * whenever:
 *   - SLAB_VERSION is incremented in slabs.h
 *   - SLABDB_VERSION is incremented in slabdb.h
 *   - a new dir inode format is introduced and defaulted to in dirinodes.h
 *     (see DIRINODE_FORMAT).
 *
 * MINOR should be updated whenever backward-compatible feature updates
 * are committed, and PATCH for any other backward-compatible change
 * (usually bug fix or minor updates that do not alter functionality).
 */
#ifndef VERSION
#define VERSION "3.0.1"
#endif

#endif
