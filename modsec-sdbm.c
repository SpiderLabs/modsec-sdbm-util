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
 * gcc modsec-sdbm.c -g `pkg-config apr-1 apr-util-1 --libs --cflags` -o modsec-sdbm
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


int verbose = 0;
int print_unpack = 0;
int print_only_expireds = 0;

#define v(fmt, ARGS...) do { if (verbose) printf("%s:%d:%s(): " fmt, __FILE__, \
        __LINE__, __func__, ## ARGS); } while (0)
#define p(fmt, ARGS...) do { printf(fmt, ## ARGS); } while (0)

int open_sdbm(apr_pool_t *pool, apr_sdbm_t **db, const char *name)
{
    apr_status_t ret = APR_SUCCESS;
    char *guessed_name = NULL;

    v("Trying to open: %s\n", name);

    ret = apr_sdbm_open(db, name, APR_CREATE | APR_WRITE | APR_SHARELOCK, 0x0777, pool);
    if (ret == APR_SUCCESS)
    {
        goto ok_to_go;
    }

    if (strlen(name) < 5) /* .ext  + 1 */
        goto failed;

    guessed_name = strndupa(name, strlen(name)-4);

    v("Trying to open: %s\n", guessed_name);
    ret = apr_sdbm_open(db, guessed_name, APR_CREATE | APR_WRITE | APR_SHARELOCK, 0x0777, pool);
    /* free(guessed_name); */
    if (ret == APR_SUCCESS)
    {
        goto ok_to_go;
    }

failed:
    return -1;
ok_to_go:

    v("File opened.\n");
    return 0;
}


int expired(apr_pool_t *pool, const unsigned char *blob, unsigned int blob_size)
{
    unsigned int blob_offset;

    blob_offset = 3;
    while (blob_offset + 1 < blob_size)
    {
        char *name;
        int name_len;

        name_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        if (name_len == 0)
        {
            /* Is the length a name length, or just the end of the blob? */
            if (blob_offset < blob_size - 2)
            {
                /* This should never happen as the name length
                 * includes the terminating NUL and should be 1 for ""
                 */
                v("Maybe we have a corruption... the string goes boynd the allocated space.\n");
            }
            break;
        }
        else if (name_len > 65536)
        {
            /* This should never happen as the length is restricted on store
             * to 65536.
             */
            v("Possibly corrupted database: var name length > 65536 (0x%04x) at blob offset %u-%u.", name_len, blob_offset, blob_offset + 1);
            break;
        }

        blob_offset += 2;
        if (blob_offset + name_len > blob_size)
        {
            return ;
        }

        name = strndup((const char *)blob + blob_offset, name_len - 1);
        blob_offset += name_len;
        name_len--;

        int value_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        blob_offset += 2;

        if (blob_offset + value_len > blob_size)
        {
            return;
        }

        char *value = strndup((const char *)blob + blob_offset, value_len - 1);

        blob_offset += value_len;
        value_len--;

        /*printf("%30s: %s\n", name, value);*/
        if (strcmp("__expire_KEY", name) == 0)
        {
            int start = atoi(value);
            int end = time(NULL);
            v("Expired: %d, %d delta: %d\n", start, end, end-start);

            if (end-start > 0)
                return 1;

            return 0;
        }

    }
    return  0;
}


void unpack(apr_pool_t *pool, const unsigned char *blob, unsigned int blob_size)
{
    unsigned int blob_offset;

    printf(" - ModSecurity variables:\n");

    blob_offset = 3;
    while (blob_offset + 1 < blob_size)
    {
        char *name;
        int name_len;

        name_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        if (name_len == 0)
        {
            /* Is the length a name length, or just the end of the blob? */
            if (blob_offset < blob_size - 2)
            {
                /* This should never happen as the name length
                 * includes the terminating NUL and should be 1 for ""
                 */
                v("Maybe we have a corruption... the string goes boynd the allocated space.\n");
            }
            break;
        }
        else if (name_len > 65536)
        {
            /* This should never happen as the length is restricted on store
             * to 65536.
             */
            v("Possibly corrupted database: var name length > 65536 (0x%04x) at blob offset %u-%u.", name_len, blob_offset, blob_offset + 1);
            break;
        }

        blob_offset += 2;
        if (blob_offset + name_len > blob_size)
        {
            return ;
        }

        name = strndup((const char *)blob + blob_offset, name_len - 1);
        blob_offset += name_len;
        name_len--;

        int value_len = (blob[blob_offset] << 8) + blob[blob_offset + 1];
        blob_offset += 2;

        if (blob_offset + value_len > blob_size)
        {
            return;
        }

        char *value = strndup((const char *)blob + blob_offset, value_len - 1);
        blob_offset += value_len;
        value_len--;

        printf("%30s: %s\n", name, value);

    }
}

static int dump_database(apr_pool_t *pool, apr_sdbm_t *db)
{
    apr_status_t ret;
    apr_sdbm_datum_t key;
    apr_sdbm_datum_t val;
    
    ret = apr_sdbm_firstkey(db, &key);
    if (ret != APR_SUCCESS) {
        v("Failed to retrieve the first key of the database.\n");
        goto failed;
    }

    do {
        ret = apr_sdbm_fetch(db, &val, key);
        if (ret != APR_SUCCESS) {
            v("Failed to fetch the value of the key: %s.\n", key.dptr);
            goto failed;
        }

        if (print_only_expireds && !expired(pool, (const unsigned char *)val.dptr, val.dsize))
            continue;

        printf("Key: \"%s\", Value len: %d\n", key.dptr, val.dsize);

        if (print_unpack)
        {
            unpack(pool, (const unsigned char *)val.dptr, val.dsize);
        }

        ret = apr_sdbm_nextkey(db, &key);
        if (ret != APR_SUCCESS) {
            v("Failed to retrieve the next key.\n");
            goto failed;
        }
    } while (key.dptr);

    return 0;
failed:
    return -1;
}

static int shrink_db(apr_pool_t *pool, apr_sdbm_t *db)
{
    apr_status_t ret;
    apr_sdbm_datum_t key;
    apr_sdbm_datum_t val;
    apr_sdbm_t *new_db = NULL;
    char *new_db_file = "/tmp/shrinked-sdbm"; // FIXME: shoud be a parameter.
    int expd = 0;
    int others = 0;
    int dots = 0;
    int elements = 0;

    ret = apr_sdbm_open(&new_db, new_db_file, APR_CREATE | APR_WRITE | APR_SHARELOCK, 0x0777, pool);
    if (ret != APR_SUCCESS) {
        v("Failed to create the newest database\n");
        goto failed;
    }


    printf ("Shrinking database.... \n");
    ret = apr_sdbm_firstkey(db, &key);
    if (ret != APR_SUCCESS) {
        v("Failed to retrieve the first key of the database.\n");
        goto failed;
    }

    do {
        ret = apr_sdbm_fetch(db, &val, key);
        if (ret != APR_SUCCESS) {
            v("Failed to fetch the value of the key: %s.\n", key.dptr);
            goto failed;
        }

        if (val.dsize == 0) {
            others++;
            goto next_item;
        }

        if (expired(pool, (const unsigned char *)val.dptr, val.dsize)) {
            expd++;
            goto next_item;
        }

        ret = apr_sdbm_store(new_db, key, val, APR_SDBM_INSERT);
        if (ret != APR_SUCCESS)
        {
            v("Failed to insert an element in the newest table\n");
            goto failed;
        }

next_item:
        if (others + expd % 10 == 0)
        {
            dots++;
            if (dots % 80 == 0)
                printf("\n");
            printf(".");
        }

        ret = apr_sdbm_nextkey(db, &key);
        if (ret != APR_SUCCESS) {
            v("Failed to retrieve the next key.\n");
            goto failed;
        }
        elements++;
    } while (key.dptr);

//FIXME>
    printf("\n");
    printf("Total of %d elements on the original database\n", elements);
    printf("%d elements removed.\n", expd+others);
    printf("(Expired: %d, others: %d)\n", expd, others);
    printf("Reduced in %2.2d%%\n", 100*(expd+others)/elements);
    apr_sdbm_close(new_db);

    return 0;
failed:
    printf("\n");
    printf("Total of %d elements on the original database\n", elements);
    printf("%d elements removed.\n", expd+others);
    printf("(Expired: %d, others: %d)\n", expd, others);
    printf("Reduced in %2.2d%%\n", 100*(expd+others)/elements);
    apr_sdbm_close(new_db);


    return -1;
}

int remove_key (apr_pool_t *pool, apr_sdbm_t *db, const char *key_str)
{
    apr_status_t ret;
    apr_sdbm_datum_t key;

    v("Deleting key: %s\n", key_str);

    key.dptr = (char *)strdup(key_str);
    key.dsize = strlen(key_str)+1;

    ret = apr_sdbm_delete(db, key);

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


void hello (void) {

    p("\n modsec-sdbm\n\n");

    p(" This utility was created in order to make easy the maintenance of the SDBM files\n");
    p(" which stores ModSecurity persistent collections.\n\n");

    p("  -k, shrink: Removes all the expired elements as long as others not well\n");
    p("\tformated items from the database. It does create a new database;\n");
    p("  -s, status: Print information about the table, such us the amount of item,\n");
    p("\tamount of expired items and also the amount of malformed items that\n");
    p("\tmay be using space;\n");
    p("  -d, dump: Dump all the items of the database on the `stdout`;\n");
    p("  -u, unpack: Interpret the content of the value as ModSecurity does, printing\n");
    p("\tthe results on the conosle. (This does not make sense without the\n");
    p("\t-d option);\n");
    p("  -x, expired: Print only the expired elements. (As unpack, this item does not\n");
    p("\tmake sense whitout the dump option);\n");
    p("  -r, remove: Expects to receive a key as a paramter to be removed;\n");
    p("  -v, verbose: Some extra information about what this utility is doing.\n");
    p("  -h, help: this message.\n\n");

}

int main (int argc, char **argv)
{
    apr_pool_t *pool;

    int shrink = 0;
    int status = 0;
    int dump = 0;
    char *to_remove = NULL;

    char *cvalue = NULL;
    int index;
    int c;
     
    opterr = 0;


    if (argc < 2)
    {
        hello();
        return 0;
    }

    while ((c = getopt (argc, argv, "kxsdahvur:")) != -1)
    switch (c)
    {
        case 'k':
            shrink = 1;
            break;
        case 's':
            status = 1;
            break;
        case 'd':
            dump = 1;
            break;
        case 'r':
            to_remove = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'u':
            print_unpack = 1;
            break;
        case 'x':
            print_only_expireds = 1;
            break;
        case '?':
            if (optopt == 'r')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            hello();
            return 1;
            case 'h':
        default:
            hello();
    }


    v("shrink = %d, status = %d, dump = %d, verbose = %d to remove: %s\n", shrink, status, dump, verbose, to_remove);

    apr_initialize();
    /* atexit(apr_terminate()); */

    apr_pool_create(&pool, NULL);

    for (index = optind; index < argc; index++)
    {
        int ret = 0;
        apr_sdbm_t *db = NULL;
        char *file = argv[index];

        printf ("Openning file: %s\n", file);
        ret = open_sdbm(pool, &db, argv[index]);
        if (ret < 0)
        {
            printf("Failed to open sdbm: %s", file);
            goto that_is_all_folks;
        }

        if (shrink)
            shrink_db(pool, db);

        if (to_remove)
            remove_key(pool, db, to_remove);

        if (dump)
            dump_database(pool, db);

        apr_sdbm_close(db);
    }

    apr_pool_destroy(pool);

that_is_all_folks:
    return 0;
}


