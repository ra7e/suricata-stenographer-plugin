/* Copyright (C) 2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Vadym Malakhatko <v.malakhatko@sirinsoftware.com>
 */

#ifndef __UTIL_STENOGRAPHER_H__
#define __UTIL_STENOGRAPHER_H__

#include <stdint.h>
#include <stdio.h>
#include <curl/curl.h>
#include <unistd.h>

/**
 * This holds global structures and variables. 
 */
typedef struct AlertStenographerCtx_ {
    const char *pcap_dir;
    uint32_t before_time;
    uint32_t after_time;
    int compression;
    int no_overlapping;
    int cleanup;
    const char *cleanup_script;
    unsigned long cleanup_expiry_time;
    unsigned long min_disk_space_left;
    FILE *fptr;
} AlertStenographerCtx;

#include <curl/curl.h>

static int IsDirectoryWritable(const char* dir)
{
    if (access(dir, W_OK) == 0)
        return 1;
    return 0;
}

static int IsFileExist(const char* fname)
{
    if( access(fname, F_OK) == 0 ) {
        return 1;
    } else {
        return 0;
    }
}

static int IsLogDirectoryWritable(const char* str)
{
    if (access(str, W_OK) == 0)
        return 1;
    return 0;
}

void SCLogStenographerInit(char *url, long port,
    char *pCertFile, char *pKeyName, char * pCACertFile);
int LogStenographerFileWrite(void *lf_ctx, const char *file_path, const char* start_time, const char* end_time);

#endif /* __UTIL_STENOGRAPHER_H__ */
