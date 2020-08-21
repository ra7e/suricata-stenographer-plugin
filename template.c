#include <stdio.h>
#include <stdlib.h>

#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"
#include "threads.h"
#include "util-stenographer"

#define OUTPUT_NAME "template-filetype-plugin"


static int TemplateWrite(const char *buffer, int buffer_len, void *data) {
    AlertStenographerCtx *ctx = data;
    return 0;
}

static void TemplateClose(void *data) {
    printf("TemplateClose\n");
    AlertStenographerCtx *ctx = data;
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

static int TemplateOpen(ConfNode *conf, void **data) {
        
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    AlertStenographerCtx *ctx;
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertStenographerInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }
    char * pcap_dir = ConfNodeLookupChildValue(conf, "pcap-dir");
    char * s_before_time = ConfNodeLookupChildValue(conf, "before-time");

    uint32_t before_time = 0;
    if (s_before_time != NULL) {
            if (ParseSizeStringU32(s_before_time, &before_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    before_time);
                exit(EXIT_FAILURE);
            }
            // TODO add limits
            /*if (pl->size_limit < 4096) {
                SCLogInfo("pcap-log \"limit\" value of %"PRIu64" assumed to be pre-1.2 "
                        "style: setting limit to %"PRIu64"mb", pl->size_limit, pl->size_limit);
                uint64_t size = pl->size_limit * 1024 * 1024;
                pl->size_limit = size;
            } else if (pl->size_limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize pcap-log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }*/
        }
    char * s_after_time = ConfNodeLookupChildValue(conf, "after-time");
    uint32_t after_time = 0;
    if (s_after_time != NULL) {
            if (ParseSizeStringU32(s_after_time, &after_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    after_time);
                exit(EXIT_FAILURE);
            }
            // TODO add limits
            /*if (pl->size_limit < 4096) {
                SCLogInfo("pcap-log \"limit\" value of %"PRIu64" assumed to be pre-1.2 "
                        "style: setting limit to %"PRIu64"mb", pl->size_limit, pl->size_limit);
                uint64_t size = pl->size_limit * 1024 * 1024;
                pl->size_limit = size;
            } else if (pl->size_limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize pcap-log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }*/
        }

    int compression = False;
    char * s_compression = ConfNodeLookupChildValue(conf, "compression");
    if(ConfValIsTrue(s_compression)) {
        compression = True;
    }

    int no_overlapping = False;

    
    char * s_no_overlapping = ConfNodeLookupChildValue(conf, "no-overlapping");
    if(ConfValIsTrue(s_no_overlapping)) {
        no_overlapping = True;
    }

    int cleanup = False;
    char * cleanup_script;

    ConfNode *cleanup_node = NULL;
    
    cleanup_node = ConfNodeLookupChild(conf, "cleanup");
    uint64_t expiry_time = 0;
    uint64_t min_disk_space_left = 0;
    if (cleanup_node != NULL && ConfNodeChildValueIsTrue(cleanup_node, "enabled")) {
        cleanup = True;
        const char *script = ConfNodeLookupChildValue(cleanup_node, "script");

        if (script != NULL) {
            cleanup_script = script;
        }
        char * s_expiry_time = ConfNodeLookupChildValue(cleanup_node, "expiry-time");
    
        if (s_expiry_time != NULL) {
            if (ParseSizeStringU64(s_expiry_time, &expiry_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    after_time);
                exit(EXIT_FAILURE);
            }
        }
        
        char * s_min_disk_space_left = ConfNodeLookupChildValue(cleanup_node, "min-disk-space-left");
    
        if (s_min_disk_space_left != NULL) {
            if (ParseSizeStringU64(s_min_disk_space_left, &min_disk_space_left) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    after_time);
                exit(EXIT_FAILURE);
            }
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }
    ctx = SCMalloc(sizeof(AlertStenographerCtx));
    ctx->pcap_dir = pcap_dir;
    ctx->before_time = before_time;
    ctx->after_time = after_time;
    ctx->compression = compression;
    ctx->no_overlapping = no_overlapping;
    ctx->cleanup = cleanup;
    ctx->cleanup_script = cleanup_script;
    ctx->cleanup_expiry_time = expiry_time;
    ctx->min_disk_space_left = min_disk_space_left;
    ctx->logfile_ctx = logfile_ctx;
    if (unlikely(ctx == NULL)) {
        //prelude_perror(ret, "Unable to allocate memory");
        //prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        //SCReturnCT(result, "OutputInitResult");
    }

    *data = ctx;
    return 0;
}

/**
 * Called by Suricata to initialize the module. This module registers
 * new file type to the JSON logger.
 */
void TemplateInit(void)
{
    SCPluginFileType *my_output = SCCalloc(1, sizeof(SCPluginFileType));
    my_output->name = OUTPUT_NAME;
    my_output->Open = TemplateOpen;
    my_output->Write = TemplateWrite;
    my_output->Close = TemplateClose;
    if (!SCPluginRegisterFileType(my_output)) {
        FatalError(SC_ERR_PLUGIN, "Failed to register filetype plugin: %s", OUTPUT_NAME);
    }
}

const SCPlugin PluginSpec = {
    .name = OUTPUT_NAME,
    .author = "Vadym Malakhatko <v.malakhatko@sirinsoftware.com>",
    .license = "GPLv2",
    .Init = TemplateInit,
};


#include <dirent.h>
#include <sys/stat.h>

int CleanupOldest (char *dirname, time_t expiry, char * script_before_cleanup) {

    int script_run = 0;
    DIR * directory; 
    struct stat buf;
    struct dirent *entry;
    int retcode, num_ents;
    char *filename, *cwd;
    time_t now;

    num_ents = 0; /* Number of entries left in current directory */

    /* Open target directory */
    directory = opendir(dirname);
    if (directory == NULL) {
        fprintf(stderr, "%s: ", dirname);
        perror ("Unable to read directory");
        return -1;
    }
    if ((chdir(dirname) == -1)) {
        fprintf(stderr, "%s: ", dirname);
        perror("chdir failed");
        return -1;
    }
  
    /* Process directory contents, deleting all regular files with
     * mtimes more than expiry seconds in the past */

    now = time(NULL);  
    while ((entry = readdir(directory))) {
        filename = entry->d_name;

        /* Ignore '.' and '..' */
        if (! strcmp(filename,".")  ) { continue; }
        if (! strcmp(filename,"..") ) { continue; }
    
        //num_ents ++; /* New entry, count it */
    
        retcode = lstat(filename, &buf);
        if (retcode == -1) {
            fprintf(stderr, "%s: ", filename);
            perror("stat failed");
            continue;
        }

        if (S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)) {
            /* File or symlink- check last modification time */
            if ((now - expiry) > buf.st_mtime) {
                unlink (filename);
                if(script_run == 0) {
                    system(script_before_cleanup);
                    script_run = 1;
                }

                num_ents ++;
            }
        }
        /*else if (S_ISDIR(buf.st_mode)) {
               
            if (CleanupOldest(filename, expiry) == 0) {
                   
                rmdir(filename); 
                num_ents ++;
            }
        }*/
    }
    closedir(directory);
    chdir("..");
    return num_ents;
}

int CleanupNeeded() {
    return 1;
}

#include <sys/statvfs.h>

long GetAvailableDiskSpace(const char* path) {
    struct statvfs stat;

  if (statvfs(path, &stat) != 0) {
    // error happens, just quits here
    return -1;
  }

  // the available size is f_bsize * f_bavail
  return stat.f_bsize * stat.f_bavail;
}