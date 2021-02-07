#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h> 
#include "util-misc.h"
#include "util-time.h"
#include "suricata-plugin.h"
#include "util-debug.h"
#include "util-stenographer.h"
#include <dirent.h>
#include <sys/stat.h>

#define OUTPUT_NAME "stenographer-plugin"

int CleanupOldest (const char *dirname, time_t expiry, const char * script_before_cleanup, FILE *fptr);

#include <sys/statvfs.h>
#include <time.h>

void CreateIsoTimeStringNoMS (const struct timeval *ts, char *str, size_t size)
{
    const time_t time = ts->tv_sec;
    struct tm local_tm;
    memset(&local_tm, 0, sizeof(local_tm));
    struct tm *t = gmtime(&time);
    char time_fmt[64] = { 0 };

    if (likely(t != NULL)) {
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%SZ", t);
        snprintf(str, size, time_fmt, ts->tv_usec);
    } else {
        snprintf(str, size, "ts-error");
    }
}

long GetAvailableDiskSpace(const char* path) {
    struct statvfs stat;

  if (statvfs(path, &stat) != 0) {
    // error happens, just quits here
    return -1;
  }

  // the available size is f_bsize * f_bavail
  return stat.f_bsize * stat.f_bavail;
}

/* The largest that size allowed for one alert string. */
#define MAX_STENOGRAPHER_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_STENOGRAPHER_BUFFER_SIZE (2 * MAX_STENOGRAPHER_ALERT_SIZE)

void* savePcap(void *data) {
    AlertStenographerCtx *ctx = (AlertStenographerCtx *)data;
    
    while (1) {

        sleep(1);
        pthread_mutex_lock(&ctx->pcap_saver_mutex);
        Alert current_alert;
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        while(!q_isEmpty(&ctx->alert_queue)) {
            
        if(!q_peek(&ctx->alert_queue, &current_alert)) {
            goto end_current_check;
        }

        // cannot create pcap now (end time is in future (cannot save packets from future))
        if (current_alert.end_time.tv_sec > current_time.tv_sec) {
            pthread_mutex_unlock(&ctx->pcap_saver_mutex);
            goto end_current_check;
        }
        
        q_pop(&ctx->alert_queue, &current_alert);
        
        char timebuf[64];
        
        CreateTimeString(&current_alert.alert_time, timebuf, sizeof(timebuf));
        
        char stenographerPcapAlertFile[64];
        //sprintf(stenographerPcapAlertFile, "%s-%s-%s", "alert", "test", timebuf);
        CreateIsoTimeString(&current_alert.alert_time, stenographerPcapAlertFile, sizeof(stenographerPcapAlertFile));
        
        
        char alert_buffer[MAX_STENOGRAPHER_BUFFER_SIZE];
        fprintf(ctx->fptr, "%s\n", current_alert.buffer);
        
        if(ctx->compression) {
            fprintf(ctx->fptr, "Alert Pcap saved to file : %s.lz4 \n", stenographerPcapAlertFile);
        }
        else {
            fprintf(ctx->fptr, "Alert Pcap saved to file : %s.pcap \n", stenographerPcapAlertFile);
        }
        fflush(ctx->fptr);

        char end_timebuf[64];
        CreateIsoTimeStringNoMS(&current_alert.end_time, end_timebuf, sizeof(end_timebuf));
        
        char start_timebuf[64];
        CreateIsoTimeStringNoMS(&current_alert.start_time, start_timebuf, sizeof(start_timebuf));

        if(ctx->cleanup) {
            if(ctx->cleanup_expiry_time) {
                int files_deleted = CleanupOldest(ctx->pcap_dir, ctx->cleanup_expiry_time, ctx->cleanup_script, ctx->fptr);
                if(files_deleted) {
                    char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                    int cleanup_size = 0;
                    snprintf(cleanup_message, MAX_STENOGRAPHER_ALERT_SIZE,
                        "%s Cleanup of the folder '%s' is finished, %d file(s) older than %lu seconds were deleted \n", timebuf, ctx->pcap_dir, files_deleted, ctx->cleanup_expiry_time);
                    fprintf(ctx->fptr, "%s", cleanup_message);
                }
            }
            if(ctx->min_disk_space_left) {
                if(ctx->min_disk_space_left > GetAvailableDiskSpace(ctx->pcap_dir)) {
                    int files_deleted = CleanupOldest(ctx->pcap_dir, 0, ctx->cleanup_script, ctx->fptr);
                    if(files_deleted) {
                        char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                        int cleanup_size = 0;
                        snprintf(cleanup_message, MAX_STENOGRAPHER_ALERT_SIZE,
                            "%s Cleanup of the folder '%s' is finished, %d file(s) were deleted, %lu bytes of empty space left \n", timebuf, ctx->pcap_dir, files_deleted, GetAvailableDiskSpace(ctx->pcap_dir));
                        fprintf(ctx->fptr, "%s", cleanup_message);
                    }
                }
            }
        }
            LogStenographerFileWrite((void *)ctx, stenographerPcapAlertFile, start_timebuf, end_timebuf);
        }
        end_current_check:
        pthread_mutex_unlock(&ctx->pcap_saver_mutex);

    }
}

static int TemplateWrite(const char *buffer, int buffer_len, void *data) {

    json_t *root;
    json_error_t error;
    AlertStenographerCtx *ctx = data;

    root = json_loadb(buffer, buffer_len, 0, &error);

    if (root) {
        json_t * type = json_object_get(root, "event_type");
        json_t * proto = json_object_get(root, "proto");
        if (strcmp(json_string_value(type), "alert") != 0) {
            json_decref(root);
            return 0;
        }
    } else {
        json_decref(root);
        return 0;
    }
    json_decref(root);
    
    int i;
    int decoder_event = 0;
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    struct timeval end_time;
    end_time.tv_sec = current_time.tv_sec + ctx->after_time;
    end_time.tv_usec = current_time.tv_usec;
    
    struct timeval start_time;
    start_time.tv_sec = current_time.tv_sec - ctx->before_time;
    start_time.tv_usec = current_time.tv_usec;

    Alert alert = {start_time, end_time, current_time, buffer};

    pthread_mutex_lock(&ctx->pcap_saver_mutex);
    q_push(&ctx->alert_queue, &alert);
    pthread_mutex_unlock(&ctx->pcap_saver_mutex);

    return 0;
}

static void TemplateClose(void *data) {
    //printf("TemplateClose\n");
    AlertStenographerCtx *ctx = data;

    if (ctx != NULL) {
        fclose(ctx->fptr);
        SCFree(ctx);
    }
    pthread_cancel(ctx->pcap_saver_thread);
    
}

static int TemplateOpen(ConfNode *conf, void **data) {
    AlertStenographerCtx *ctx;
    
    const char * pcap_dir = ConfNodeLookupChildValue(conf, "pcap-dir");
    if (ConfigCheckLogDirectoryExists(pcap_dir) != TM_ECODE_OK) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "Stenographer pcap logging directory \"%s\" "
                "doesn't exist. Shutting down the engine", pcap_dir);
        exit(EXIT_FAILURE);
    }

    if (!IsDirectoryWritable(pcap_dir)) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "Stenographer pcap logging directory \"%s\" "
                "is not writable. Shutting down the engine", pcap_dir);
        exit(EXIT_FAILURE);
    }

    const char * log_file = ConfNodeLookupChildValue(conf, "filename");
    FILE *fptr = fopen(log_file, "a");
    if (fptr == NULL) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "Stenographer logging file \"%s\" "
                "cannot be created. Shutting down the engine", log_file);
        exit(EXIT_FAILURE);
    }

    const char * cert_dir = ConfNodeLookupChildValue(conf, "cert-dir");
    if (ConfigCheckLogDirectoryExists(cert_dir) != TM_ECODE_OK) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "Stenographer cert directory \"%s\" "
                "doesn't exist. Shutting down the engine", pcap_dir);
        exit(EXIT_FAILURE);
    }

    const char * s_before_time = ConfNodeLookupChildValue(conf, "before-time");

    uint32_t before_time = 0;
    if (s_before_time != NULL) {
        if (ParseSizeStringU32(s_before_time, &before_time) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize pcap output, invalid limit: %d", before_time);
                exit(EXIT_FAILURE);
        }
    }
    const char * s_after_time = ConfNodeLookupChildValue(conf, "after-time");
    uint32_t after_time = 0;
    if (s_after_time != NULL) {
        if (ParseSizeStringU32(s_after_time, &after_time) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize pcap output, invalid limit: %d", after_time);
            exit(EXIT_FAILURE);
        }
    }

    int compression = 0;
    const char * s_compression = ConfNodeLookupChildValue(conf, "compression");
    if(ConfValIsTrue(s_compression)) {
        compression = 1;
    }

    int no_overlapping = 0;

    
    const char * s_no_overlapping = ConfNodeLookupChildValue(conf, "no-overlapping");
    if(ConfValIsTrue(s_no_overlapping)) {
        no_overlapping = 1;
    }

    int cleanup = 0;
    const char * cleanup_script;

    ConfNode *cleanup_node = NULL;
    
    cleanup_node = ConfNodeLookupChild(conf, "cleanup");
    uint64_t expiry_time = 0;
    uint64_t min_disk_space_left = 0;
    if (cleanup_node != NULL && ConfNodeChildValueIsTrue(cleanup_node, "enabled")) {
        cleanup = 1;
        const char *script = ConfNodeLookupChildValue(cleanup_node, "script");

        if (script != NULL) {
            cleanup_script = script;
        }

        if (IsFileExist(cleanup_script) != TM_ECODE_OK) {
            SCLogError(SC_ERR_LOGDIR_CONFIG, "Stenographer cleanup script \"%s\" "
                "doesn't exist. Shutting down the engine", pcap_dir);
                exit(EXIT_FAILURE);
        }
        const char * s_expiry_time = ConfNodeLookupChildValue(cleanup_node, "expiry-time");
    
        if (s_expiry_time != NULL) {
            if (ParseSizeStringU64(s_expiry_time, &expiry_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %d",
                    after_time);
                exit(EXIT_FAILURE);
            }
        }
        
        const char * s_min_disk_space_left = ConfNodeLookupChildValue(cleanup_node, "min-disk-space-left");
    
        if (s_min_disk_space_left != NULL) {
            if (ParseSizeStringU64(s_min_disk_space_left, &min_disk_space_left) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %d",
                    after_time);
                exit(EXIT_FAILURE);
            }
        }
    }
    ctx = SCMalloc(sizeof(AlertStenographerCtx));
    q_init(&ctx->alert_queue, sizeof(Alert), UINT16_MAX, IMPLEMENTATION, true);
    pthread_cond_init(&ctx->new_alert, NULL);
    
    ctx->pcap_dir = pcap_dir;
    ctx->before_time = before_time;
    ctx->after_time = after_time;
    ctx->compression = compression;
    ctx->no_overlapping = no_overlapping;
    ctx->cleanup = cleanup;
    ctx->cleanup_script = cleanup_script;
    
    char *client_cert = (char *)malloc(strlen(cert_dir) + 15);
    sprintf(client_cert, "%s%s", cert_dir, "client_cert.pem");
    char *client_key = (char *)malloc(strlen(cert_dir) + 14);
    sprintf(client_key, "%s%s", cert_dir, "client_key.pem");
    char *ca_cert = (char *)malloc(strlen(cert_dir) + 11);
    sprintf(ca_cert, "%s%s", cert_dir, "ca_cert.pem");

    ctx->client_cert = client_cert;
    ctx->client_key = client_key;
    ctx->ca_cert = ca_cert;

    
    ctx->cleanup_expiry_time = expiry_time;
    ctx->min_disk_space_left = min_disk_space_left;
    ctx->fptr = fptr;

    *data = ctx;

    pthread_create(&ctx->pcap_saver_thread, NULL, savePcap, (void *)ctx);
    pthread_mutex_init ( &ctx->pcap_saver_mutex, NULL);
    return 0;
}

int CleanupOldest (const char *dirname, time_t expiry,const char * script_before_cleanup, FILE * fptr) {

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
        //fprintf(stderr, "%s: ", dirname);
        fprintf(fptr, "Unable to read directory");
        return -1;
    }
    if ((chdir(dirname) == -1)) {
        //fprintf(stderr, "%s: ", dirname);
        fprintf(fptr, "chdir failed");
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
            //fprintf(stderr, "%s: ", filename);
            fprintf(fptr, "stat failed");
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
    }
    closedir(directory);
    chdir("..");
    return num_ents;
}

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

const SCPlugin PluginRegistration = {
    .name = OUTPUT_NAME,
    .author = "Vadym Malakhatko <v.malakhatko@sirinsoftware.com>",
    .license = "GPLv2",
    .Init = TemplateInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}