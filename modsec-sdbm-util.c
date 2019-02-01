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

#include "apr.h"
#include "apr_lib.h"
#include "apr_errno.h"
#include "apr_file_io.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_sdbm.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>

#if !defined(VERSION)
#define VERSION "v1.0"
#endif
#define PRGNAME "modsec_sdbm_util"

#ifdef WIN32
# define v  if (verbose) printf
#else
# define v(fmt, ARGS...) do { if (verbose) printf("%s:%d:%s(): " fmt, __FILE__, \
        __LINE__, __func__, ## ARGS); } while (0)
#endif


#define PRINT               0x00000010
#define PRINT_ONLY_EXPIRED  0x00000100
#define PRINT_MODSEC_VARS   0x00001000
#define SHRINK              0x00010000
#define STATUS              0x00100000
#define EXTRACT             0x01000000
#define IS_EXPIRED          0x10000000


#define PROGRESS_STAT_SIZE 6
static char progress_feedback[PROGRESS_STAT_SIZE] = {'|', '/', '-', '|', '\\', '-'};
static int verbose = 0;
static const char *shortname;

static char *xstrndup(const char *s, size_t n)
{
    char *res;
    const char *end;

    if (s == NULL) {
        return NULL;
    }
    end = memchr(s, '\0', n);
    if (end != NULL)
        n = end - s;
    res = malloc(n + 1);
    memcpy(res, s, n);
    res[n] = '\0';
    return res;
}

static apr_status_t open_sdbm(apr_pool_t *pool, apr_sdbm_t **db, const char *name)
{
    apr_status_t rv;
    char        *guessed_name = NULL;

    v("Trying to open database: %s\n", name);
    rv = apr_sdbm_open(db, name, APR_WRITE | APR_SHARELOCK,
                       0x0777, pool);
    if (rv == APR_SUCCESS) {
        goto ok_to_go;
    }

    if (strlen(name) < 5) /* .ext  + 1 */
        goto failed;

    guessed_name = apr_pstrndup(pool, name, strlen(name) - 4);

    v("Trying to open database: %s\n", guessed_name);
    rv = apr_sdbm_open(db, guessed_name, APR_WRITE | APR_SHARELOCK,
                       0x0777, pool);
    if (rv == APR_SUCCESS) {
        goto ok_to_go;
    }

failed:
    v("Failed to open database.\n");
    return rv;
ok_to_go:
    v("Database opened.\n");
    return APR_SUCCESS;
}

static apr_status_t modsec_unpack(apr_pool_t *pool, const unsigned char *blob,
                                  unsigned int blob_size, int action)
{
    unsigned int blob_offset = 0;
    apr_status_t rv = APR_SUCCESS;


    while (blob_offset + 1 < blob_size) {
        char *name;
        char *value;
        int   name_len;
        int   value_len;

        name_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        if (name_len == 0) {
            /* Is the length a name length, or just the end of the blob? */
            if (blob_offset < blob_size - 2) {
                /* This should never happen as the name length
                 * includes the terminating NUL and should be 1 for ""
                 */
                v("Maybe we have a corruption... the string goes beyond the " \
                  "allocated space.\n");
            }
            break;
        }
        else if (name_len > 65536) {
            /* This should never happen as the length is restricted on store
             * to 65536.
             */
            v("Possibly corrupted database: var name length > 65536 (0x%04x) " \
              "at blob offset %u-%u.", name_len, blob_offset,
                   blob_offset + 1);
            /* XXX: We should probably bail out since the database
             * is corrupted
             */
            break;
        }

        blob_offset += 2;
        if (blob_offset + name_len > blob_size) {
            /* TODO: print some error message
             */
            return rv;
        }

        name = xstrndup((const char *)blob + blob_offset, name_len - 1);
        blob_offset += name_len;
        name_len--;

        value_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        blob_offset += 2;
        if (blob_offset + value_len > blob_size) {
            free(name);
            return rv;
        }
        value = xstrndup((const char *)blob + blob_offset, value_len - 1);

        blob_offset += value_len;
        value_len--;

        if (action & IS_EXPIRED) {
            if (strcmp("__expire_KEY", name) == 0) {
                time_t start = atoi(value);
                time_t end   = time(NULL);
                v("Expired: %ld, %ld delta: %ld\n", start, end, end - start);

                if ((end - start) > 0)
                    rv = APR_EOF;
            }
        }
        if (action & PRINT) {
            fprintf(stdout, "%30s: %s\n", name, value);
        }
        free(name);
        free(value);
    }
    return rv;
}


static void print_modsec_variables(apr_pool_t *pool, const unsigned char *blob,
                                   unsigned int blob_size)
{
    fprintf(stdout, " - ModSecurity variables:\n");
    modsec_unpack(pool, blob, blob_size, PRINT);
}

static apr_status_t is_expired(apr_pool_t *pool, const unsigned char *blob, unsigned int blob_size)
{
    return modsec_unpack(pool, blob, blob_size, IS_EXPIRED);
}

static apr_status_t remove_datum_t(apr_pool_t *pool, apr_sdbm_t *db, apr_sdbm_datum_t *key)
{
    apr_status_t rv = apr_sdbm_delete(db, *key);

    if (rv == APR_SUCCESS) {
        v("Deleted successfully.\n");
    }
    else {
        char errmsg[250];
        v("Failed to delete %s\n",
          apr_strerror(rv, errmsg, sizeof(errmsg)));
    }
    return rv;
}

static apr_status_t dump_database(apr_pool_t *pool, apr_sdbm_t *db,
                                  int action, char *new_db_path)
{
    apr_status_t     rv;
    apr_sdbm_datum_t key;
    apr_sdbm_datum_t val;
    apr_sdbm_t      *db_dest;
    double  elements = 0;
    int     bad_datum = 0;
    int     expired_datum = 0;
    int     removed = 0;
    int     progress = 0;
    char   *db_name = NULL;

    if (action & PRINT) {
        v("Dumping database...\n");
    }
    if (action & SHRINK) {
        v("Starting the shrink process...\n");
    }
    if (action & STATUS) {
        v("Showing some status about the databases...\n");
    }

    if (action & EXTRACT) {
        apr_filepath_merge(&db_name, new_db_path,
                           "new_db", APR_FILEPATH_NATIVE, pool);
        v("Exporting valid items to: %s.[pag,dir]...\n", db_name);
        
        rv = apr_sdbm_open(&db_dest, db_name,
                           APR_CREATE | APR_WRITE | APR_SHARELOCK, 0x0777, pool);

        if (rv != APR_SUCCESS) {
            v("Failed to retrieve the first key of the database.\n");
            return rv;
        }
    }

    rv = apr_sdbm_firstkey(db, &key);
    if (rv != APR_SUCCESS) {
        v("Failed to retrieve the first key of the database.\n");
        goto end;
    }

    do {
        rv = apr_sdbm_fetch(db, &val, key);
        if (rv != APR_SUCCESS) {
            v("Failed to fetch the value of the key: %s.\n", key.dptr);
            break;
        }

        elements++;

        if (action & PRINT) {
            if ((!(action & PRINT_ONLY_EXPIRED)) ||
                ((action & PRINT_ONLY_EXPIRED) &&
                is_expired(pool, (const unsigned char *)val.dptr, val.dsize))) {
                fprintf(stdout, "Key: \"%s\", Value len: %d\n", key.dptr, val.dsize);
                if (action & PRINT_MODSEC_VARS) {
                    print_modsec_variables(pool,
                            (const unsigned char *)val.dptr, val.dsize);
                }
            }
        }

        if ((action & SHRINK) || (action & STATUS) || (action & EXTRACT)) {
            int selected = 0;

            if (val.dsize == 0) {
                bad_datum++;
                selected = 1;
            }

            if (is_expired(pool, (const unsigned char *)val.dptr, val.dsize)) {
                expired_datum++;
                selected = 1;
            }

            if ((int)elements % 10 == 0) {
                progress = (progress + 1) % PROGRESS_STAT_SIZE;
                fprintf(stdout, " [%c] %.0f records so far.\r",
                        progress_feedback[progress], elements);
                fflush(stdout);
            }

            if (selected && (action & SHRINK)) {
                rv = remove_datum_t(pool, db, &key);
                if (rv != APR_SUCCESS) {
                    fprintf(stderr, "Failed to delete key: \"%s\"\n",
                            (const char *)key.dptr);
                } else {
                    removed++;
                }
                /* Remove key.
                 */
            }

            if ((selected == 0) && (action & EXTRACT)) {
                rv = apr_sdbm_store(db_dest, key, val, APR_SDBM_INSERT);
                if (rv != APR_SUCCESS) {
                    fprintf(stderr, "Failed to insert key: \"%s\"\n",
                            (const char *)key.dptr);
                }

            }

        }

        rv = apr_sdbm_nextkey(db, &key);
        if (rv != APR_SUCCESS) {
            if (rv == APR_EOF) {
                v("No more records in the database.\n");
            }
            else {
                v("Failed to retrieve the next key.\n");
            }
            break;
        }
    } while(key.dptr);

end:
    if (action & EXTRACT) {
        fprintf(stdout, "New database generated with valid keys at: %s\n", db_name);
        apr_sdbm_close(db_dest);
    }
    if ((action & SHRINK) || (action & STATUS)) {
        fprintf(stdout, "\n");
        fprintf(stdout, "Total of %.0f elements processed.\n", elements);
        fprintf(stdout, "%d elements removed.\n", removed);
        fprintf(stdout, "Expired elements: %d, inconsistent items: %d\n",
               expired_datum, bad_datum);
        if (expired_datum + bad_datum != 0 && elements != 0) {
            fprintf(stdout, 
                    "Fragmentation rate: %2.2f%% of the database is/was dirty data.\n",
                    100 * (expired_datum + bad_datum) / elements);
        }
    }

    return rv;
}

static apr_status_t remove_key(apr_pool_t *pool, apr_sdbm_t *db, char *key_str)
{
    apr_sdbm_datum_t key;

    v("Deleting key: %s\n", key_str);

    key.dptr  = key_str;
    key.dsize = (int)strlen(key_str) + 1;

    return remove_datum_t(pool, db, &key);
}

static void version(void)
{
    fprintf(stderr, "%s %s\n\n", shortname, VERSION);
}

static void usage(void) {

    fprintf(stderr,
        "Usage: %s [nkxsdahVvurD] <database-name>\n\n", shortname);
    fprintf(stderr,
        "This utility was created in order to make easy the maintenance of the SDBM files\n"
        "which stores ModSecurity persistent collections.\n\n"
        "  -k, shrink: Removes all the expired elements as long as others not well\n"
        "      formated items from the database.\n"
        "  -n, new: Extract valid items of a database to a new one. Output will be:\n"
        "      /tmp/new_db.[dir,pag] unless otherwise specified using the -D option.\n"
        "  -D, directory: Used with -n, expects to receive a directory path in which the\n"
        "      the resulting new_db.[dir,pag] files are placed.\n"
        "  -s, status: Print information about the table, such us the amount of items,\n"
        "      amount of expired items and also the amount of malformed items that\n"
        "      tmay be using space;\n"
        "  -d, dump: Dump all database items to `stdout`;\n"
        "  -u, unpack: Interpret the content of the value as ModSecurity does, printing\n"
        "      the results to the console. (This does not make sense without the\n"
        "     -d option);\n"
        "  -x, expired: Print only the expired elements. (As unpack, this item does not\n"
        "      make sense without the dump option);\n"
        "  -r, remove: Expects to receive a key as a paramter to be removed;\n"
        "  -V. version: Print version information.\n"
        "  -v, verbose: Some extra information about what this utility is doing.\n"
        "  -h, help: this message.\n"
        "\n");

}

int main (int argc, const char * const argv[])
{
    apr_pool_t   *pool;
    char         *to_remove   = NULL;
    char         *new_db_path = NULL;
    char          c;
    int           action = 0;
    apr_dir_t    *db_dest_dir;
    apr_getopt_t *opt;
    const char   *opt_arg;
    apr_status_t  rv;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    if ((rv = apr_pool_create(&pool, NULL)) != APR_SUCCESS) {
        return rv;
    }
    if (argc) {
        shortname = apr_filepath_name_get(argv[0]);
    }
    else {
        shortname = PRGNAME;
    }
    if (argc < 2) {
        usage();
        return APR_EINVAL;
    }

    apr_getopt_init(&opt, pool, argc, argv);

    while ((rv = apr_getopt(opt, "nkxsdahVvur:D:", &c, &opt_arg)) == APR_SUCCESS) {
        switch (c) {
            case 'd':
                action |= PRINT;
                break;
            case 'u':
                action |= PRINT_MODSEC_VARS;
                break;
            case 'x':
                action |= PRINT_ONLY_EXPIRED;
                break;
            case 'k':
                action |= SHRINK;
                break;
            case 's':
                action |= STATUS;
                break;
            case 'n':
                action |= EXTRACT;
                break;
            case 'D':
                new_db_path = apr_pstrdup(pool, opt_arg);
                break;
            case 'r':
                to_remove = apr_pstrdup(pool, opt_arg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'V':
                version();
                return 0;
            case 'h':
                usage();
                return 0;
            default:
                break;
        }
    }
    if (rv != APR_EOF) {
        usage();
        return rv;
    }

    if (argc <= opt->ind) {
        fprintf(stderr, "No database name was provided.\n");
        usage();
        return APR_EINVAL;
    }

    if (new_db_path == NULL) {
        if ((rv = apr_temp_dir_get((const char **)&new_db_path, pool)) != APR_SUCCESS) {
            usage();
            return rv;
        }
    }
    /* Test to see if the target directory exists
     */
    v("Checking target directory: %s\n", new_db_path);
    rv = apr_dir_open(&db_dest_dir, new_db_path, pool);
    if (rv != APR_SUCCESS) {
        char errmsg[250];
        fprintf(stderr, "Could not open target directory %s: %s\n",
                new_db_path, apr_strerror(rv, errmsg, sizeof(errmsg)));
        return rv;
    }
    apr_dir_close(db_dest_dir);
    v("Target directory exists.\n");

    while (opt->ind < argc) {
        apr_sdbm_t *db = NULL;

        v("Using database: %s\n", argv[opt->ind]);
        rv = open_sdbm(pool, &db, argv[opt->ind]);
        if (rv != APR_SUCCESS) {
            fprintf(stderr, "Failed to open sdbm: %s\n", argv[opt->ind]);
            break;
        }
        v("Database ready to be used.\n");

        if (to_remove) {
            v("Removing key: %s\n", to_remove);
            remove_key(pool, db, to_remove);
            opt->ind++;
            continue;
        }
        if (action == 0) {
            /* XXX: This message looks weird.
             * If there is no action specified should we bail out
             * before opening database?
             */
            fprintf(stderr, "Choose an option.\n");
            usage();
            rv = APR_EINVAL;
            break;
        }

        dump_database(pool, db, action, new_db_path);
        apr_sdbm_close(db);
        opt->ind++;
    }

    return rv;
}
