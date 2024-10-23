#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings

// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
char * tryWord(char * plaintext, char * hashFilename)
{
    //  Hash word
    char *hash = md5(plaintext, strlen(plaintext));

    //  Open the hash file
    FILE *fp = fopen(hashFilename, "r");
    if (!fp)
    {
        puts("Cant open hashFile for reading");
        exit(1);
    }

    //  Allocate enough memory for each hashstring
    char *line = malloc(sizeof(char) * HASH_LEN);

    //  Loop through the hash file, one line at a time.
    while (fgets(line, sizeof(char) * HASH_LEN, fp))
    {
        //  Trim newline
        char *nl = strchr(line, '\n');
        if (nl) *nl ='\0';

        //  Return the hash
        //  if plaintext has a matching hash in hash_file
        if (strcmp(line, hash) == 0)
        {
            fclose(fp);
            return hash;
        }
    }

    //  Close file and free memory
    fclose(fp);
    free(hash);

    //  Return NULL if not found
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }
    
    //  Open the dictionary file for reading.
    FILE *d = fopen(argv[2], "r");
    if (!d)
    {
        puts("Cant open dictionary for reading");
        exit(1);
    }

    //  Allocate enough memory for the maximum password
    char *line = malloc(sizeof(char) * PASS_LEN);
    int count = 0;

    //  For each line in the dictionary file
    while (fgets(line, sizeof(char) * PASS_LEN, d))
    {
        //  Trim newline
        char *nl = strchr(line, '\n');
        if (nl) *nl ='\0';

        //  Pass each word to tryWord
        //  match it against the hashes in the hash_file
        char *found = tryWord(line, argv[1]);

        //  Display the hash and the dictionaryWord if there's a match
        if (found)
        {
            printf("%s %s\n", found, line);
            free(found);
            count++;
        }
    }
    
    fclose(d);
    printf("%d hashes cracked!\n", count);
}
