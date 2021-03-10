#include <stdio.h>
#include "util-stenographer.h"

/**
 * @brief                           Deleting files function 
 * 
 * @param dirname                   Name of a directory
 * @param expiry                    Expiry value of file, parameter 0 produse deleting all files
 * @param script_before_cleanup     Name of script to store files in cloud befor cleaning
 * @param fptr                      Pointer to error-log file
 * @return int                      Returns total number of deleted files
 */
int CleanupOldest(const char *dirname, time_t expiry, const char * script_before_cleanup, FILE *fptr);

/**
 * @brief                Function determines the reason of cleaning then call the cleaning function
 * 
 * @param ctx            Structure with global variables 
 * @param timebuf        This buffer contains string in format "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
                                                                  month, day, year, hour, min, sec, usec);
 * @param disk_space     Value of free disk space in bytes
 * @return int           Returns 0 when everething is OK, othrwise return -1
 */
int CleanupBegin(AlertStenographerCtx *ctx, char *timebuf, long);
