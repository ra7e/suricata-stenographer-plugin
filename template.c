#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h> 
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <time.h>

#include "cleanup.h"
#include "util-misc.h"
#include "util-time.h"
#include "suricata-plugin.h"
#include "util-debug.h"
#include "util-stenographer.h"

#define OUTPUT_NAME "stenographer-plugin"

/**
 * @brief Formating timeval to readable format  
 * 
 * @param ts pointer to timeval struct
 * @param str pointer to destination string
 * @param size max number of bytes that will be written to str
 */
static void CreateIsoTimeStringNoMS (const struct timeval *ts, char *str, size_t size)
{
    const time_t time = ts->tv_sec; //store seconds to $time, time_t consider only seconds
    struct tm local_tm;
    memset(&local_tm, 0, sizeof(local_tm)); //fill $local_tm with zeros to avoid troubles 
    struct tm *t = gmtime(&time); // convert time_t format to tm, means convert big number of seconds to acceptable format
    char time_fmt[64] = { 0 }; 

    if (likely(t != NULL)) {
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%SZ", t);
        snprintf(str, size, time_fmt, ts->tv_usec);
    } else {
        snprintf(str, size, "ts-error");
    }
}
/**
 * @brief Get the Available Disk Space object
 * 
 * @param path path to any file in mounted filesystem
 * @return long returns value of free disk space in bytes
 */
static long GetAvailableDiskSpace(const char* path) {
    struct statvfs stat;

  if (statvfs(path, &stat) != 0) {
    // error happens, just quits here
    return -1;
  }
  return stat.f_bsize * stat.f_bavail;
}

/* The largest that size allowed for one alert string. */
#define MAX_STENOGRAPHER_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_STENOGRAPHER_BUFFER_SIZE (2 * MAX_STENOGRAPHER_ALERT_SIZE)
#define SIZE 33     //maximum lenght of external alert   

/**
 * @brief Reads up to 33 symbols of alert name from named pipe \    
 *        stores name and time parameters into "Alert" struct \
 *        then push struct to alert queue
 * 
 * @param ctx global structure
 */
void getAlertFromFifo(AlertStenographerCtx *ctx) {
    
    char *buf = malloc(sizeof(char) * SIZE+1);

    if(NULL == buf)
    {
        fprintf(ctx->fptr, "Error trying allocate memory");
        return;
    }

    memset(buf, 0, sizeof(buf));

    if(ctx->command_pipe_fd <= 2){
        fprintf(ctx->fptr, "Invalid file descriptor for named pipe-[%d]\n", ctx->command_pipe_fd);
        return;
    }

    ssize_t data = 0;
    while (data = read(ctx->command_pipe_fd, buf, SIZE+1) > 0){}
    
    if(strlen(buf))
    {
        size_t length = strlen(buf);
        buf[length -1] = '\0';

        struct timeval current_time;
        gettimeofday(&current_time, NULL);

        struct timeval end_time;
        end_time.tv_sec = current_time.tv_sec + ctx->after_time;
        end_time.tv_usec = current_time.tv_usec;
        
        struct timeval start_time;
        start_time.tv_sec = current_time.tv_sec - ctx->before_time;
        start_time.tv_usec = current_time.tv_usec;

        Alert alert = {start_time, end_time, current_time, buf, buf};
        
        pthread_mutex_lock(&ctx->pcap_saver_mutex);
        q_push(&ctx->alert_queue, &alert);
        pthread_mutex_unlock(&ctx->pcap_saver_mutex);
    }
}
/**
 * @brief Main function, handle all alerts \ 
 *        creates .pcap filenames and call \
 *        write to disk function 
 * 
 * @param data global variable struct
 * @return void* pointer to savePcap function
 */
void* savePcap(void *data) {
    AlertStenographerCtx *ctx = (AlertStenographerCtx *)data;
    while (1) 
    {
        sleep(1);
        getAlertFromFifo(ctx);
        pthread_mutex_lock(&ctx->pcap_saver_mutex);
        Alert current_alert;
        struct timeval current_time;
        gettimeofday(&current_time, NULL);

        while(!q_isEmpty(&ctx->alert_queue)) 
        {
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
        
            char stenographerPcapAlertFile_time[64] = {0}; 
            char stenographerPcapAlertFile_full[128] = {0};

            strcpy(stenographerPcapAlertFile_full, current_alert.name);
            
            free((char*)current_alert.name);
            
            CreateIsoTimeString(&current_alert.alert_time, stenographerPcapAlertFile_time, sizeof(stenographerPcapAlertFile_time));
            
            strcat(stenographerPcapAlertFile_full, ".");
            strcat(stenographerPcapAlertFile_full, stenographerPcapAlertFile_time);
            
            printf("Full name - %s\n", stenographerPcapAlertFile_full);

            char alert_buffer[MAX_STENOGRAPHER_BUFFER_SIZE];
            fprintf(ctx->fptr, "%s\n", current_alert.buffer);
            
            if(ctx->compression) {
                fprintf(ctx->fptr, "Alert Pcap saved to file : %s.lz4 \n", stenographerPcapAlertFile_full);
            }
            else {
                fprintf(ctx->fptr, "Alert Pcap saved to file : %s.pcap \n", stenographerPcapAlertFile_full);
            }
            fflush(ctx->fptr);

            char end_timebuf[64];
            CreateIsoTimeStringNoMS(&current_alert.end_time, end_timebuf, sizeof(end_timebuf));
            
            char start_timebuf[64];
            CreateIsoTimeStringNoMS(&current_alert.start_time, start_timebuf, sizeof(start_timebuf));
    
            if(ctx->cleanup) 
            {
                if(!CleanupBegin(ctx, timebuf, GetAvailableDiskSpace(ctx->pcap_dir))){
                    fprintf(ctx->fptr, "Failed to clean everthing up on \"%s\" file\n", stenographerPcapAlertFile_full);
                }
            }
            LogStenographerFileWrite((void *)ctx, stenographerPcapAlertFile_full, start_timebuf, end_timebuf);
        }
        end_current_check:
        pthread_mutex_unlock(&ctx->pcap_saver_mutex);

    }
}
/**
 * @brief Process string to JSON object \
 *        pars current object and store to "Alert" structure
 *        with time parameteres 
 * 
 * @param buffer JSON string
 * @param buffer_len length of JSON string
 * @param data global variable struct
 * @return int 0 on success or lack of "alert", otherwise -1
 */
static int TemplateWrite(const char *buffer, int buffer_len, void *data) 
{
    json_t *root;
    json_error_t error;
    AlertStenographerCtx *ctx = data;

    root = json_loadb(buffer, buffer_len, 0, &error);
    char *name;

    if (root) 
    {
        json_t * type = json_object_get(root, "event_type");
        json_t * proto = json_object_get(root, "proto");
        if (strcmp(json_string_value(type), "alert") == 0) 
        {
            json_t *key_alert = json_object_get(root, "alert");
            if(json_is_object(key_alert))
            {
                json_t *signature = json_object_get(key_alert, "signature");
                if(!json_is_string(signature)){
                    fprintf(ctx->fptr, "Error parsing JSON, can`t find 'signature'\n");
                    name = "SuricataAlert.";
                    json_decref(key_alert);
        
                }else{
                    name = malloc(sizeof(char) * 20);  
                    strcpy(name, json_string_value(signature));
                }
            }
            else
            {
                name = "SuricataAlert.\0";    
            }
        }
        else{
            return 0;
        }
    }else {
        fprintf(ctx->fptr, "Error crearing new JSON reference\n");
        json_decref(root);
        return 1;
    }

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

    Alert alert = {start_time, end_time, current_time, buffer, name};

    //printf("alert.name - %s\n", alert.name);
    
    pthread_mutex_lock(&ctx->pcap_saver_mutex);
    if(!q_push(&ctx->alert_queue, &alert))
    {
        fprintf(ctx->fptr, "Queue is full\n");
    }
       
    pthread_mutex_unlock(&ctx->pcap_saver_mutex);

    json_decref(root);

    return 0;
}
/**
 * @brief Close working flow
 * 
 * @param data global variable struct 
 */
static void TemplateClose(void *data) {

    AlertStenographerCtx *ctx = data;

    if (ctx != NULL) {
        fclose(ctx->fptr);
        if(ctx->command_pipe_enabled) {
            close(ctx->command_pipe_fd);
        }
        SCFree(ctx);
    }
    pthread_cancel(ctx->pcap_saver_thread);
}
/**
 * @brief Pars configuration file .yaml and store results to AlertStenographerCtx struct
 * 
 * @param conf pointer to ConfNode 
 * @param data global variable struct
 * @return int 0 on success
 */
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

    bool command_pipe_enabled = false;
    int command_pipe_fd = -1;
    const char * command_pipe = ConfNodeLookupChildValue(conf, "command-pipe");

    if (command_pipe != NULL) 
    {
        if (!ConfValIsFalse(command_pipe)) {
            command_pipe_enabled = true;

            if((command_pipe_fd = open(command_pipe, 0666 | O_NONBLOCK)) <= 0)  {
                printf("Cant open - %s\n", command_pipe);
                if(mkfifo(command_pipe, 0666) != 0) {
                    printf("Cant create pipe - %s\n", command_pipe);
                    SCLogError(SC_ERR_LOGDIR_CONFIG, "Suricata-Stenographer plugin cannot create fifo file \"%s\" "
                        ". Shutting down the engine", command_pipe);
                    exit(EXIT_FAILURE);
                } 
                if((command_pipe_fd = open(command_pipe, 0666)) <= 0)
                {
                    SCLogError(SC_ERR_LOGDIR_CONFIG, "Suricata-Stenographer plugin cannot create fifo file \"%s\" "
                        ". Shutting down the engine", command_pipe);
                    exit(EXIT_FAILURE);
                }   
            }
            printf("Pipe name is - %s fd - %d \n", command_pipe, command_pipe_fd);
        }
    }

    const char * s_before_time = ConfNodeLookupChildValue(conf, "before-time");

    uint32_t before_time = 0;
    if (s_before_time != NULL) {
        if ((before_time = SCParseTimeSizeString(s_before_time)) == 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize before time, invalid value: %s", s_before_time);
                exit(EXIT_FAILURE);
        }
    }

    const char * s_after_time = ConfNodeLookupChildValue(conf, "after-time");
    uint32_t after_time = 0;
    if (s_after_time != NULL) {
         if ((after_time = SCParseTimeSizeString(s_after_time)) == 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize after time, invalid value: %s", s_after_time);
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
            if ((expiry_time = SCParseTimeSizeString(s_expiry_time)) == 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize expiry time, invalid limit: %ld", expiry_time);
                exit(EXIT_FAILURE);
            }
        }
        
        const char * s_min_disk_space_left = ConfNodeLookupChildValue(cleanup_node, "min-disk-space-left");
    
        if (s_min_disk_space_left != NULL) {
            if (ParseSizeStringU64(s_min_disk_space_left, &min_disk_space_left) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %ld", min_disk_space_left);
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
    
    if(NULL == client_cert){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    char *client_key = (char *)malloc(strlen(cert_dir) + 14);
    
    if(NULL == client_key){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    char *ca_cert = (char *)malloc(strlen(cert_dir) + 11);
    
    if(NULL == ca_cert){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    sprintf(client_cert, "%s%s", cert_dir, "client_cert.pem");
    sprintf(client_key, "%s%s", cert_dir, "client_key.pem");
    sprintf(ca_cert, "%s%s", cert_dir, "ca_cert.pem");

    ctx->client_cert = client_cert;
    ctx->client_key = client_key;
    ctx->ca_cert = ca_cert;

    ctx->command_pipe_enabled = command_pipe_enabled;
    ctx->command_pipe_fd = command_pipe_fd;
    
    ctx->cleanup_expiry_time = expiry_time;
    ctx->min_disk_space_left = min_disk_space_left;
    ctx->fptr = fptr;

    *data = ctx;

    if(pthread_create(&ctx->pcap_saver_thread, NULL, savePcap, (void *)ctx) != 0)
    {  
        SCLogError(SC_ERR_THREAD_CREATE, "Can`t create new thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_init(&ctx->pcap_saver_mutex, NULL);
    return 0;
}

/**
 * @brief Assign main plugin functions to Suricata
 * 
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
/**
 * @brief Define parameters of plugin
 * 
 */
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