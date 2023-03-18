/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

/*
 * Use the follwoing command to get it compiled:
 * gcc modsec-sdbm-util.c -g `pkg-config apr-1 apr-util-1 --libs --cflags` -o modsec-sdbm-util 
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <apr.h>
#include <apr_errno.h>
#include <apr_general.h>
#include <apr_want.h>
#include <apr_allocator.h>
#include <apr_sdbm.h>
#include <time.h>

#define VERSION "v1.0"

#ifndef WIN32
# define v(fmt, ARGS...) do { if (verbose) printf("%s:%d:%s(): " fmt, __FILE__, \
        __LINE__, __func__, ## ARGS); } while (0)
# define p(fmt, ARGS...) do { printf(fmt, ## ARGS); } while (0)
#endif
#ifdef WIN32
#define p  printf
#define v  if (verbose) printf
#endif
#define p2  if (!quiet) printf

#define IS_EXPIRED 128

#define PRINT 2
#define PRINT_ONLY_EXPIRED 4
#define PRINT_MODSEC_VARS 8
#define SHRINK 16
#define STATUS 32
#define EXTRACT 64


int verbose = 0, quiet = 0;
static char progress_feedback[] = {'|', '/', '-', '\\'};


int open_sdbm(apr_pool_t *pool, apr_sdbm_t **db, const char *name)
{
    apr_status_t ret = APR_SUCCESS;
    char *guessed_name = NULL;

    v("Trying to open: %s\n", name);

    ret = apr_sdbm_open(db, name, APR_WRITE | APR_SHARELOCK, 0x0777, pool);
    if (ret == APR_SUCCESS)
    {
        goto ok_to_go;
    }

    if (strlen(name) < 5) /* .ext  + 1 */
        goto failed;

    guessed_name = strndup(name, strlen(name)-4);

    v("Trying to open: %s\n", guessed_name);
    ret = apr_sdbm_open(db, guessed_name, APR_WRITE | APR_SHARELOCK,
            0x0777, pool);
    free(guessed_name);

    if (ret == APR_SUCCESS)
    {
        goto ok_to_go;
    }

failed:
    v("Failed to open.\n");
    return -1;
ok_to_go:
    v("File opened.\n");
    return 0;
}

int modsec_unpack(apr_pool_t *pool, const unsigned char *blob,
        unsigned int blob_size, int action)
{
    unsigned int blob_offset;
    int ret;


    ret = 0;
    blob_offset = 3;

    while (blob_offset + 1 < blob_size)
    {
        char *name;
        char *value;
        int name_len;
        int value_len;

        name_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        if (name_len == 0)
        {
            /* Is the length a name length, or just the end of the blob? */
            if (blob_offset < blob_size - 2)
            {
                /* This should never happen as the name length
                 * includes the terminating NUL and should be 1 for ""
                 */
                v("Maybe we have a corruption... the string goes beyond the " \
                        "allocated space.\n");
            }
            break;
        }
        else if (name_len > 65536)
        {
            /* This should never happen as the length is restricted on store
             * to 65536.
             */
            v("Possibly corrupted database: var name length > 65536 (0x%04x) " \
                   " at blob offset %u-%u.", name_len, blob_offset,
                   blob_offset + 1);
            break;
        }

        blob_offset += 2;
        if (blob_offset + name_len > blob_size)
        {
            return ret;
        }

        name = strndup((const char *)blob + blob_offset, name_len - 1);
        blob_offset += name_len;
        name_len--;

        value_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        blob_offset += 2;
        if (blob_offset + value_len > blob_size)
        {
            return ret;
        }
        value = strndup((const char *)blob + blob_offset, value_len - 1);

        blob_offset += value_len;
        value_len--;

        if (action & IS_EXPIRED)
        {
            if (strcmp("__expire_KEY", name) == 0)
            {
                int start = atoi(value);
                int end = time(NULL);
                v("Expired: %d, %d delta: %d\n", start, end, end-start);

                if (end-start > 0)
                    ret = 1;
            }
        }
        if (action & PRINT)
            printf("%30s: %s\n", name, value);

    }
    return ret;
}


void print_modsec_variables(apr_pool_t *pool, const unsigned char *blob, unsigned int blob_size)
{
    p(" - ModSecurity variables:\n");
    modsec_unpack(pool, blob, blob_size, PRINT);
}

int is_expired(apr_pool_t *pool, const unsigned char *blob, unsigned int blob_size)
{
    return modsec_unpack(pool, blob, blob_size, IS_EXPIRED);
}

int remove_datum_t(apr_pool_t *pool, apr_sdbm_t *db, apr_sdbm_datum_t *key)
{
    int ret = 0;

    ret = apr_sdbm_delete(db, *key);

    if (ret == APR_SUCCESS)
    {
        v("Deleted successfully.\n");
        return 0;
    }

    v("apr_sdbm_rdonly? %d\n", apr_sdbm_rdonly(db));
    v("APR_EINVAL? %d\n", APR_EINVAL);
    v("ret ==  %d\n", ret);

    v("Failed to delete.\n");
    return -1;
}

static int dump_database(apr_pool_t *pool, apr_sdbm_t *db, int action, char *new_db_path)
{
    apr_status_t ret;
    apr_sdbm_datum_t key;
    apr_sdbm_datum_t val;
    apr_sdbm_t *db_dest;
    double elements = 0;
    int bad_datum = 0;
    int expired_datum = 0;
    int removed = 0;
    int progress = 0;
    int fret = 0;

    if (action & PRINT)
        v("Dumping database...\n");
    if (action & SHRINK)
        v("Starting the shrink process...\n");
    if (action & STATUS)
        v("Showing some status about the databases...\n");

    if (action & EXTRACT)
    {
       
        char *file_name = "/new_db";
        int full_len = 1 + strlen(new_db_path) + strlen(file_name); 
        char *full_path = (char *) malloc(full_len);
        if (!full_path) {
            v("Cannot allocate memory.\n");
            fret = -1;
            goto end;
        }
        
        strcpy(full_path, new_db_path);
        strcat(full_path, file_name);
        full_path[full_len] = '\0';
  
        v("Exporting valid items to: %s.[pag,dir]...\n",full_path);
        
        ret = apr_sdbm_open(&db_dest, full_path,
                APR_CREATE | APR_WRITE | APR_SHARELOCK, 0x0777, pool);

        if (ret != APR_SUCCESS)
        {
            v("Failed to retrieve the first key of the database.\n");
            fret = -1;
            goto end;
        }
    }

    ret = apr_sdbm_firstkey(db, &key);
    if (ret != APR_SUCCESS)
    {
        v("Failed to retrieve the first key of the database.\n");
        fret = -1;
        goto end;
    }

    do {
        ret = apr_sdbm_fetch(db, &val, key);
        if (ret != APR_SUCCESS) {
            v("Failed to fetch the value of the key: %s.\n", key.dptr);
            fret = -1;
            goto end;
        }

        elements++;

        if (action & PRINT)
        {
            if ((!(action & PRINT_ONLY_EXPIRED)) ||
                    ((action & PRINT_ONLY_EXPIRED) && is_expired(pool,
                    (const unsigned char *)val.dptr, val.dsize)))
            {
                printf("Key: \"%s\", Value len: %d\n", key.dptr, val.dsize);
                if (action & PRINT_MODSEC_VARS)
                {
                    print_modsec_variables(pool,
                            (const unsigned char *)val.dptr, val.dsize);
                }
            }
        }

        if (action & SHRINK || action & STATUS || action & EXTRACT)
        {
            int selected = 0;
            if (val.dsize == 0) {
                bad_datum++;
                selected = 1;
            }

            if (is_expired(pool, (const unsigned char *)val.dptr, val.dsize))
            {
                expired_datum++;
                selected = 1;
            }

            if ((int)elements % 10 == 0)
            {
                int p2s = (int) progress++ % 4;
                p(" [%c] %.0f records so far.\r", progress_feedback[p2s],
                        elements);
                fflush(stdout);
            }

            if (selected && action & SHRINK)
            {
                ret = remove_datum_t(pool, db, &key);
                if (ret != APR_SUCCESS)
                {
                    p("Failed to delete key: \"%s\"\n", (const unsigned char *)key.dptr);
                } else {
                    removed++;
                }
                //Remove key.
            }

            if (selected == 0 && action & EXTRACT)
            {
                ret = apr_sdbm_store(db_dest, key, val, APR_SDBM_INSERT);
                if (ret != APR_SUCCESS)
                {
                    p("Failed to insert key: \"%s\"\n", (const unsigned char *)key.dptr);
                }

            }

        }

        ret = apr_sdbm_nextkey(db, &key);
        if (ret != APR_SUCCESS) {
            v("Failed to retrieve the next key.\n");
            fret = -1;
            goto end;
        }
    } while (key.dptr);

end:
    if (action & EXTRACT)
    {
        p("New database generated with valid keys at: %s/new_db\n", new_db_path);
        apr_sdbm_close(db_dest);
    }
    if (action & SHRINK || action & STATUS)
    {
        p2("\n");
        p2("Total of %.0f elements processed.\n", elements);
        p2("%d elements removed.\n", removed);
        p2("Expired elements: %d, inconsistent items: %d\n", expired_datum,
            bad_datum);
        if (expired_datum+bad_datum != 0 && elements !=0)
            p2("Fragmentation rate: %2.2f%% of the database is/was dirty " \
                "data.\n", 100*(expired_datum+bad_datum)/elements);
    }

    return fret;
}

int remove_key (apr_pool_t *pool, apr_sdbm_t *db, char *key_str)
{
    apr_sdbm_datum_t key;

    v("Deleting key: %s\n", key_str);

    key.dptr = key_str;
    key.dsize = strlen(key_str)+1;

    return remove_datum_t(pool, db, &key);
}

void version (void) {
    p("\n modsec-sdbm-util %s\n\n", VERSION);
}

void help (void) {

    p("\n Usage: modsec-sdbm-util [nkxsdahVvurD] <database-name>\n\n");

    p("This utility was created in order to make easy the maintenance of the SDBM files\n");
    p("which stores ModSecurity persistent collections.\n\n");

    p("  -k, shrink: Removes all the expired elements as long as others not well\n");
    p("\tformated items from the database.\n");
    p("  -n, new: Extract valid items of a database to a new one. Output will be:\n");
    p("\t/tmp/new_db.[ip,pag] unless otherwise specified using the -D option.\n");
    p("  -D, directory: Used with -n, expects to receive a directory path in which the\n");
    p("\tthe resulting new_db.[ip,pag] files are placed.\n");
    p("  -s, status: Print information about the table, such us the amount of items,\n");
    p("\tamount of expired items and also the amount of malformed items that\n");
    p("\tmay be using space;\n");
    p("  -d, dump: Dump all database items to `stdout`;\n");
    p("  -u, unpack: Interpret the content of the value as ModSecurity does, printing\n");
    p("\tthe results to the console. (This does not make sense without the\n");
    p("\t-d option);\n");
    p("  -x, expired: Print only the expired elements. (As unpack, this item does not\n");
    p("\tmake sense without the dump option);\n");
    p("  -r, remove: Expects to receive a key as a paramter to be removed;\n");
    p("  -V. version: Print version information.\n");    
    p("  -v, verbose: Some extra information about what this utility is doing.\n");
    p("  -q, quiet: Only display needed information.\n");
    p("  -h, help: this message.\n\n");

}

int main (int argc, char **argv)
{
    apr_pool_t *pool;
    char *to_remove = NULL;
    char *new_db_path = strdup("/tmp");
    int index;
    int c;
    int action = 0;

    if (argc < 2)
    {
        help();
        return 0;
    }

    while ((c = getopt (argc, argv, "qnkxsdahVvur:D:")) != -1)
    switch (c)
    {
        case 'd':
            action = action | PRINT;
            break;
        case 'u':
            action = action | PRINT_MODSEC_VARS;
            break;
        case 'x':
            action = action | PRINT_ONLY_EXPIRED;
            break;
        case 'k':
            action = action | SHRINK;
            break;
        case 's':
            action = action | STATUS;
            break;
        case 'n':
            action = action | EXTRACT;
            break;
        case 'D':
            free(new_db_path);
            new_db_path = strdup(optarg);
            break;
        case 'r':
            to_remove = strdup(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'V':
            version();
            return 0;
        case '?':
            if (optopt == 'r')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                        "Unknown option character `\\x%x'.\n", optopt);
            help();
            return 1;
        case 'h':
        default:
            help();
            return 0;
    }

    if (optind == argc) {
        printf ("No database name was provided.\n");
        help();
        return 0;
    }

    apr_initialize();
    /* atexit(apr_terminate()); */

    apr_pool_create(&pool, NULL);

    for (index = optind; index < argc; index++)
    {
        int ret = 0;
        char *file = argv[index];
        apr_sdbm_t *db = NULL;
        apr_dir_t *db_dest_dir;

        // test to see if the target directory exists
        p2("Checking target directory: %s\n", new_db_path);
        ret = apr_dir_open(&db_dest_dir, new_db_path, pool);
        if (ret != APR_SUCCESS) {
            char errmsg[120];
            p("Could not open target directory %s: %s\n", new_db_path, apr_strerror(ret, errmsg, sizeof errmsg));
            goto that_is_all_folks;
        }
        apr_dir_close(db_dest_dir);
        p2("Target directory exists.\n");

        p2("Opening file: %s\n", file);
        ret = open_sdbm(pool, &db, argv[index]);
        if (ret < 0)
        {
            printf("Failed to open sdbm: %s\n", file);
            goto that_is_all_folks;
        }
        p2("Database ready to be used.\n");

        if (to_remove) {
            p2("Removing key: %s\n", to_remove);
            remove_key(pool, db, to_remove);
            continue;
        }
        if (action == 0)
        {
            printf("Choose an option.\n");
            help();
            goto that_is_all_folks;
        }

        dump_database(pool, db, action, new_db_path);

        apr_sdbm_close(db);
    }

    apr_pool_destroy(pool);

    free(to_remove);
    free(new_db_path);

that_is_all_folks:
    return 0;
}
