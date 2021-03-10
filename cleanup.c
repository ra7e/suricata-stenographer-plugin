#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "cleanup.h"

#define KILL_THEM_ALL 0     // delete all files
        
#define MAX_STENOGRAPHER_ALERT_SIZE 2048 /* The largest that size allowed for one alert string. */
#define MAX_STENOGRAPHER_BUFFER_SIZE (2 * MAX_STENOGRAPHER_ALERT_SIZE) /* The largest alert buffer \ 
                                                                        //that will be written at one time, possibly holding multiple alerts. */


/**
 * @brief                Function determines the reason of cleaning then call the cleaning function
 * 
 * @param ctx            Structure with global variables 
 * @param timebuf        This buffer contains string in format "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
                                                                  month, day, year, hour, min, sec, usec);
 * @param disk_space     Value of free disk space in bytes
 * @return int           Returns 0 when everething is OK, othrwise return -1
 */
int CleanupBegin(AlertStenographerCtx *ctx, char *timebuf, long disk_space)
{
    int files_deleted = 0;
    int cleanup_size = 0;
    char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
    
    if(ctx->min_disk_space_left)
    {
        files_deleted = CleanupOldest(ctx->pcap_dir, KILL_THEM_ALL, ctx->cleanup_script, ctx->fptr);
        snprintf(cleanup_message, MAX_STENOGRAPHER_ALERT_SIZE,
                "%s Cleanup of the folder '%s' is finished, %d file(s) were deleted, %lu bytes of empty space left \n", 
                timebuf, ctx->pcap_dir, files_deleted, disk_space);
        fprintf(ctx->fptr, "%s", cleanup_message);
    }    
    
    if(ctx->cleanup_expiry_time)
    {
        files_deleted = CleanupOldest(ctx->pcap_dir, ctx->cleanup_expiry_time, ctx->cleanup_script, ctx->fptr);
        snprintf(cleanup_message, MAX_STENOGRAPHER_ALERT_SIZE,
            "%s Cleanup of the folder '%s' is finished, %d file(s) older than %lu seconds were deleted \n", timebuf, ctx->pcap_dir, 
                                                                                            files_deleted, ctx->cleanup_expiry_time);
        fprintf(ctx->fptr, "%s", cleanup_message);
    }

    return 0;
}
/**
 * @brief                           Deleting files function 
 * 
 * @param dirname                   Name of a directory
 * @param expiry                    Expiry value of file, parameter 0 produse deleting all files
 * @param script_before_cleanup     Name of script to store files in cloud befor cleaning
 * @param fptr                      Pointer to error-log file
 * @return int                      Returns total number of deleted files
 */
int CleanupOldest (const char *dirname, time_t expiry,const char * script_before_cleanup, FILE * fptr) 
{
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
        if (!strcmp(filename,".") || !strcmp(filename,"..")) 
            continue; 
    
        retcode = lstat(filename, &buf);
        if (retcode == -1) {
            //fprintf(stderr, "%s: ", filename);
            fprintf(fptr, "lstat failed on %s file", entry->d_name);
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
                num_ents++; // new deleted file
            }
        }
    }
    closedir(directory);
    chdir("..");
    return num_ents;
}
