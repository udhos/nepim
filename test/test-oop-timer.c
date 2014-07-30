
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <oop.h>

#define MEGA (1000000LL)

oop_source_sys *oop_sys;
oop_source     *oop_src;
struct timeval  prev;
struct timeval  next;
int             delay;
int             interval = 0;
long long       max_intervals = 10;
long long       min_elapsed_time = 0x00FFFFFFFFFFFFFFLL;
long long       total_elapsed_time = 0;
long long       max_elapsed_time = 0;

static void schedule(void);

static void *time_handler(oop_source *src, struct timeval tv, void *user)
{
  struct timeval now;
  long long elapsed;

  assert(timercmp(&tv, &next, ==));

  {
    int result = gettimeofday(&now, 0);
    assert(!result);
  }

  elapsed = (now.tv_sec * MEGA) + now.tv_usec -
    ((prev.tv_sec * MEGA) + prev.tv_usec);

  if (elapsed < min_elapsed_time)
    min_elapsed_time = elapsed;

  if (elapsed > max_elapsed_time)
    max_elapsed_time = elapsed;

  total_elapsed_time += elapsed;

  ++interval;

#if 0
  fprintf(stderr, "DEBUG %d/%lld elapsed = %lld\n",
	  interval, max_intervals, total_elapsed_time);
#endif

  if (interval < max_intervals)
    schedule();

  return OOP_CONTINUE;
}

static void schedule(void)
{
  int result = gettimeofday(&next, 0);
  assert(!result);

  prev = next;

  next.tv_usec += delay;

  /* overflow? */
  if (next.tv_usec >= MEGA) {
    int sec = next.tv_usec / MEGA;
    next.tv_usec %= MEGA;
    next.tv_sec += sec;
  }

  assert(next.tv_usec < MEGA);

  oop_src->on_time(oop_src, next, time_handler, 0);
}

static void go()
{
  long long average;

  oop_sys = oop_sys_new();
  assert(oop_sys);

  oop_src = oop_sys_source(oop_sys);
  assert(oop_src);

  schedule();

  for (;;) {
    void *result = oop_sys_run(oop_sys);
    if (result == OOP_ERROR) {
      fprintf(stderr, "event system source error\n");
      continue;
    }
    if (result == OOP_CONTINUE) {
      fprintf(stderr, "no event sink registered\n");
      break;
    }
    if (result == OOP_HALT) {
      fprintf(stderr, "some event sink requested termination\n");
      break;
    }
    assert(0);
  }

  average = total_elapsed_time / max_intervals;

  fprintf(stdout, "RESULT: delay min = %lld us (%lld ms)\n",
	  min_elapsed_time, min_elapsed_time / 1000);
  fprintf(stdout, "RESULT: delay average = %lld us (%lld ms)\n",
	  average, average / 1000);
  fprintf(stdout, "RESULT: delay max = %lld us (%lld ms)\n",
	  max_elapsed_time, max_elapsed_time / 1000);

  oop_sys_delete(oop_sys);
} 

int main(int argc, const char *argv[])
{
  const char *prog_name = argv[0];

  if (argc != 3) {
    fprintf(stderr, "usage: %s cycles usecs\n", prog_name);
    exit(1);
  }

  max_intervals = atoi(argv[1]);
  delay = atoi(argv[2]);

  fprintf(stdout, "%s: cycles=%lld delay=%d usecs\n", prog_name,
	  max_intervals, delay);

  go();

  exit(0);
}
