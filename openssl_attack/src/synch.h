#ifndef SYNCH_H
#define SYNCH_H

typedef struct synch_ {
  unsigned long int *base;
} synch;

void synch_create();
int synch_connect(synch *s);
void synch_destroy();
void synch_sync(synch *s);

#endif /* SYNCH_H */