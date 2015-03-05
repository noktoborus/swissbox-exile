/* vim: ft=c ff=unix fenc=utf-8
 * file: fakedb/fakedb.h
 */
#ifndef _FAKEDB_FAKEDB_1425511858_H_
#define _FAKEDB_FAKEDB_1425511858_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct fdbCursor;

void fdb_open();
void fdb_close();

bool fdb_store(struct fdbCursor *c, void *data, void (*data_free)(void*));
struct fdbCursor *fdb_cursor();
void fdb_uncursor(struct fdbCursor *c);
void *fdb_walk(struct fdbCursor *c);



#endif /* _FAKEDB_FAKEDB_1425511858_H_ */

