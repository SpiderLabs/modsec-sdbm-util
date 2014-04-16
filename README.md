modsec-sdbm-util

This utility was created in order to make easy the maintenance of the SDBM files
which stores ModSecurity persistent collections.

List of options:


   * -k, shrink: Removes all the expired elements as long as others not well
      formated items from the database.
   * -n, new: Extract valid items of a database to a new one. Output will be:
      /tmp/new_db.[ip,pag]
   * -s, status: Print information about the table, such us the amount of items,
      amount of expired items and also the amount of malformed items that
      may be using space;
   * -d, dump: Dump all database items to 'stdout';
   * -u, unpack: Interpret the content of the value as ModSecurity does, printing
      the results to the console. (This does not make sense without the
      -d option);
   * -x, expired: Print only the expired elements. (As unpack, this item does not
      make sense without the dump option)
   * -r, remove: Expects to receive a key as a paramter to be removed;
   * -v, verbose: Some extra information about what this utility is doing;
   * -h, help: this message.
