/* vi: set et ts=4: */
/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 *
 * File-like output for logging:  stenographer
 */
/* errno.h, string.h, etc. */
#include "util-stenographer.h"
#include <lz4frame.h>
#include <string.h>
#include <stdlib.h>

#include <curl/curl.h>

static const char * stenographer_url = "https://127.0.0.1/query";
static long  stenographer_port = 1234L;
static const char * stenographer_client_cert_file_path = "/etc/nsm/stenographer/certs/client_cert.pem";
static const char * stenographer_client_key_file_path = "/etc/nsm/stenographer/certs/client_key.pem";
static const char * stenographer_ca_cert_file_path = "/etc/nsm/stenographer/certs/ca_cert.pem";

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t writefunc(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

/* safe_fwrite() :
 * performs fwrite(), ensure operation success, or immediately exit() */
static void safe_fwrite(void* buf, size_t eltSize, size_t nbElt, FILE* f, void * lf_ctx)
{
    size_t const writtenSize = fwrite(buf, eltSize, nbElt, f);
    size_t const expectedSize = eltSize * nbElt;
    //assert(expectedSize / nbElt == eltSize);   /* check overflow */
    if (writtenSize < expectedSize) {
        if (ferror(f))  /* note : ferror() must follow fwrite */
            fprintf(((AlertStenographerCtx *)lf_ctx)->fptr, "Write to pcap file failed \n");
        else
            fprintf(((AlertStenographerCtx *)lf_ctx)->fptr, "Short write \n");
        fflush(((AlertStenographerCtx *)lf_ctx)->fptr);
    }
}

static const LZ4F_preferences_t kPrefs = {
    { LZ4F_max256KB, LZ4F_blockLinked, LZ4F_noContentChecksum, LZ4F_frame, 0, 0, LZ4F_noContentChecksum },
    0,   /* compression level; 0 == default */
    0,   /* autoflush */
     0, 0, 0, 0 ,
};



typedef struct {
    int error;
    unsigned long long size_in;
    unsigned long long size_out;
} compressResult_t;

static compressResult_t
compress_file_internal(const char* f_in, FILE* f_out,
                       LZ4F_compressionContext_t ctx,
                       void* inBuff,  size_t inChunkSize,
                       void* outBuff, size_t outCapacity,
                       void* lf_ctx)
{
    compressResult_t result = { 1, 0, 0 };  /* result for an error */
    unsigned long long count_in = 0, count_out;

    //assert(f_in != NULL); assert(f_out != NULL);
    //assert(ctx != NULL);
    //assert(outCapacity >= 15);
    //assert(outCapacity >= LZ4F_compressBound(inChunkSize, &kPrefs));

    /* write frame header */
    {   size_t const headerSize = LZ4F_compressBegin(ctx, outBuff, outCapacity, &kPrefs);
        if (LZ4F_isError(headerSize)) {
            printf("Failed to start compression: error %u \n", (unsigned)headerSize);
            return result;
        }
        count_out = headerSize;
        // printf("Buffer size is %u bytes, header size %u bytes \n", (unsigned)outCapacity, (unsigned)headerSize);
        safe_fwrite(outBuff, 1, headerSize, f_out, lf_ctx);
    }

    /* stream file */
    
        size_t const readSize = inChunkSize;
        count_in += readSize;

        size_t const compressedSize = LZ4F_compressUpdate(ctx,
                                                outBuff, outCapacity,
                                                f_in, readSize,
                                                NULL);
        if (LZ4F_isError(compressedSize)) {
            printf("Compression failed: error %u \n", (unsigned)compressedSize);
            return result;
        }

        if(compressedSize) {
            safe_fwrite(outBuff, 1, compressedSize, f_out, lf_ctx);
            count_out += compressedSize;
        }

    /* flush whatever remains within internal buffers */
    {   size_t const compressedSize = LZ4F_compressEnd(ctx,
                                                outBuff, outCapacity,
                                                NULL);
        if (LZ4F_isError(compressedSize)) {
            printf("Failed to end compression: error %u \n", (unsigned)compressedSize);
            return result;
        }

        // printf("Writing %u bytes \n", (unsigned)compressedSize);
        safe_fwrite(outBuff, 1, compressedSize, f_out, lf_ctx);
        count_out += compressedSize;
    }

    result.size_in = count_in;
    result.size_out = count_out;
    result.error = 0;
    return result;
}

/**
 * \brief LogStenographerFileWrite() writes log data to pcap output.
 * \param log_ctx Log file context allocated by caller
 * \param string buffer with data to write
 * \param string_len data length
 * \retval 0 on sucess;
 * \retval -1 on failure;
 */
int LogStenographerFileWrite(void *lf_ctx, const char *file_path, const char* start_time, const char* end_time)
{
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);  /* will be grown as needed by realloc above */ 
  chunk.size = 0;
  
  CURL *curl;
  CURLcode res;
  
  /* In windows, this will init the winsock stuff */ 
  res = curl_global_init(CURL_GLOBAL_DEFAULT);
  /* Check for errors */ 
  if(res != CURLE_OK) {
    fprintf(((AlertStenographerCtx *)lf_ctx)->fptr, "curl_global_init() failed: %s\n",
            curl_easy_strerror(res));
    return 1;
  }

  char *postthis = (char *)malloc(70 * sizeof(char)); 
  sprintf(postthis, "after %s and before %s", start_time, end_time);  
  //printf("reauest: %s\n", postthis);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1/query");
    
    curl_easy_setopt(curl, CURLOPT_PORT, 1234L);

    curl_easy_setopt(curl, CURLOPT_SSLCERT, ((AlertStenographerCtx *)lf_ctx)->client_cert);
    curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, ((AlertStenographerCtx *)lf_ctx)->client_key);
    curl_easy_setopt(curl, CURLOPT_CAINFO, ((AlertStenographerCtx *)lf_ctx)->ca_cert);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postthis);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postthis));
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
 
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    CURLcode res = curl_easy_perform(curl);
    
    if(res != CURLE_OK) {
      fprintf(((AlertStenographerCtx *)lf_ctx)->fptr, "Request to stenographer failed: %s\n", curl_easy_strerror(res));
      fflush(((AlertStenographerCtx *)lf_ctx)->fptr);
      return 0;
    }
    FILE *fptr;
    const char * dir = ((AlertStenographerCtx *)lf_ctx)->pcap_dir;
    char *result = malloc(strlen(dir) + strlen(file_path) + 6); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, dir);
    strcat(result, file_path);
    
    // opening file in writing mode
    
    if(((AlertStenographerCtx *)lf_ctx)->compression) {
      strcat(result, ".lz4");
    fptr = fopen(result, "wb");
      LZ4F_compressionContext_t ctx;
       size_t const ctxCreation = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
       void* const src = malloc(chunk.size);
       size_t const outbufCapacity = LZ4F_compressBound(chunk.size, &kPrefs);   /* large enough for any input <= IN_CHUNK_SIZE */
       void* const outbuff = malloc(outbufCapacity);
   
       compressResult_t result = { 1, 0, 0 };  /* == error (default) */
       if (!LZ4F_isError(ctxCreation) && src && outbuff) {
           result = compress_file_internal(chunk.memory, fptr,
                                           ctx,
                                           src, chunk.size,
                                           outbuff, outbufCapacity, lf_ctx);
       } else {
           fprintf(((AlertStenographerCtx *)lf_ctx)->fptr, "error : lz4 resource allocation failed \n");
           fflush(((AlertStenographerCtx *)lf_ctx)->fptr);
       }
   
       LZ4F_freeCompressionContext(ctx);   /* supports free on NULL */
       free(src);
       free(outbuff);
 
    }
    else {
      strcat(result, ".pcap");
      fptr = fopen(result, "w");
      fwrite(chunk.memory, sizeof(char), chunk.size, fptr);
    }
    fclose(fptr);

    free(result);
    free(chunk.memory);
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }

}
