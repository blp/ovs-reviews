/* PSPP - a program for statistical analysis.
   Copyright (C) 2007, 2009, 2010, 2011, 2013, 2014, 2016 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <config.h>

#include "model-checker.h"

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "bitmap.h"
#include "deque.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

/* Initializes PATH as an empty path. */
void
mc_path_init (struct mc_path *path)
{
  path->ops = NULL;
  path->length = 0;
  path->capacity = 0;
}

/* Copies the contents of OLD into NEW. */
void
mc_path_copy (struct mc_path *new, const struct mc_path *old)
{
  if (old->length > new->capacity)
    {
      new->capacity = old->length;
      free (new->ops);
      new->ops = xmalloc (new->capacity * sizeof *new->ops);
    }
  new->length = old->length;
  memcpy (new->ops, old->ops, old->length * sizeof *new->ops);
}

/* Adds OP to the end of PATH. */
void
mc_path_push (struct mc_path *path, int op)
{
  if (path->length >= path->capacity)
    path->ops = xrealloc (path->ops, ++path->capacity * sizeof *path->ops);
  path->ops[path->length++] = op;
}

/* Removes and returns the operation at the end of PATH. */
int
mc_path_pop (struct mc_path *path)
{
  int back = mc_path_back (path);
  path->length--;
  return back;
}

/* Returns the operation at the end of PATH. */
int
mc_path_back (const struct mc_path *path)
{
  ovs_assert (path->length > 0);
  return path->ops[path->length - 1];
}

/* Destroys PATH. */
void
mc_path_destroy (struct mc_path *path)
{
  free (path->ops);
  path->ops = NULL;
}

/* Returns the operation in position INDEX in PATH.
   INDEX must be less than the length of PATH. */
int
mc_path_get_operation (const struct mc_path *path, size_t index)
{
  ovs_assert (index < path->length);
  return path->ops[index];
}

/* Returns the number of operations in PATH. */
size_t
mc_path_get_length (const struct mc_path *path)
{
  return path->length;
}

/* Appends the operations in PATH to STRING, separating each one
   with a single space. */
void
mc_path_to_string (const struct mc_path *path, struct ds *string)
{
  size_t i;

  for (i = 0; i < mc_path_get_length (path); i++)
    {
      if (i > 0)
        ds_put_char (string, ' ');
      ds_put_format (string, "%d", mc_path_get_operation (path, i));
    }
}

/* Search options. */
struct mc_options
  {
    /* Search strategy. */
    enum mc_strategy strategy;          /* Type of strategy. */
    int max_depth;                      /* Limit on depth (or INT_MAX). */
    int hash_bits;                      /* Number of bits to hash (or 0). */
    unsigned int seed;                  /* Random seed for MC_RANDOM
                                           or MC_DROP_RANDOM. */
    struct mc_path follow_path;         /* Path for MC_PATH. */

    /* Queue configuration. */
    int queue_limit;                    /* Maximum length of queue. */
    enum mc_queue_limit_strategy queue_limit_strategy;
                                        /* How to choose state to drop
                                           from queue. */

    /* Stop conditions. */
    int max_unique_states;              /* Maximum unique states to process. */
    int max_errors;                     /* Maximum errors to detect. */
    double time_limit;                  /* Maximum time in seconds. */

    /* Output configuration. */
    int verbosity;                      /* 0=low, 1=normal, 2+=high. */
    int failure_verbosity;              /* If greater than verbosity,
                                           verbosity of error replays. */
    FILE *output_file;                  /* File to receive output. */

    /* How to report intermediate progress. */
    int progress_usec;                  /* Microseconds between reports. */
    mc_progress_func *progress_func;    /* Function to call on each report. */

    /* Client data. */
    void *aux;
  };

/* Default progress function. */
bool
mc_progress_dots (struct mc *mc)
{
  if (mc_results_get_stop_reason (mc_get_results (mc)) == MC_CONTINUING)
    putc ('.', stderr);
  else
    putc ('\n', stderr);
  return true;
}

/* Progress function that prints a one-line summary of the
   current state on stderr. */
bool
mc_progress_fancy (struct mc *mc)
{
  const struct mc_results *results = mc_get_results (mc);
  if (mc_results_get_stop_reason (results) == MC_CONTINUING)
    fprintf (stderr, "Processed %d unique states, max depth %d, "
             "dropped %d duplicates...\r",
             mc_results_get_unique_state_count (results),
             mc_results_get_max_depth_reached (results),
             mc_results_get_duplicate_dropped_states (results));
  else
    putc ('\n', stderr);
  return true;
}

/* Progress function that displays a detailed summary of the
   current state on stderr. */
bool
mc_progress_verbose (struct mc *mc)
{
  const struct mc_results *results = mc_get_results (mc);

  /* VT100 clear screen and home cursor. */
  fprintf (stderr, "\033[H\033[2J");

  if (mc_results_get_stop_reason (results) == MC_CONTINUING)
    mc_results_print (results, stderr);

  return true;
}

/* Do-nothing progress function. */
static bool
null_progress (struct mc *mc OVS_UNUSED)
{
  return true;
}

/* Creates and returns a set of options initialized to the
   defaults. */
struct mc_options *
mc_options_create (void)
{
  struct mc_options *options = xmalloc (sizeof *options);

  options->strategy = MC_BROAD;
  options->max_depth = INT_MAX;
  options->hash_bits = 20;
  options->seed = 0;
  mc_path_init (&options->follow_path);

  options->queue_limit = 10000;
  options->queue_limit_strategy = MC_DROP_RANDOM;

  options->max_unique_states = INT_MAX;
  options->max_errors = 1;
  options->time_limit = 0.0;

  options->verbosity = 1;
  options->failure_verbosity = 2;
  options->output_file = stdout;
  options->progress_usec = 250000;
  options->progress_func = mc_progress_dots;

  options->aux = NULL;

  return options;
}

/* Returns a copy of the given OPTIONS. */
struct mc_options *
mc_options_clone (const struct mc_options *options)
{
  return xmemdup (options, sizeof *options);
}

/* Destroys OPTIONS. */
void
mc_options_destroy (struct mc_options *options)
{
  mc_path_destroy (&options->follow_path);
  free (options);
}

/* Returns the search strategy used for OPTIONS.  The choices
   are:

   - MC_BROAD (the default): Breadth-first search.  First tries
     all the operations with depth 1, then those with depth 2,
     then those with depth 3, and so on.

     This search algorithm finds the least number of operations
     needed to trigger a given bug.

   - MC_DEEP: Depth-first search.  Searches downward in the tree
     of states as fast as possible.  Good for finding bugs that
     require long sequences of operations to trigger.

   - MC_RANDOM: Random-first search.  Searches through the tree
     of states in random order.  The standard C library's rand
     function selects the search path; you can control the seed
     passed to srand using mc_options_set_seed.

   - MC_PATH: Explicit path.  Applies an explicitly specified
     sequence of operations. */
enum mc_strategy
mc_options_get_strategy (const struct mc_options *options)
{
  return options->strategy;
}

/* Sets the search strategy used for OPTIONS to STRATEGY.

   This function cannot be used to set MC_PATH as the search
   strategy.  Use mc_options_set_follow_path instead. */
void
mc_options_set_strategy (struct mc_options *options, enum mc_strategy strategy)
{
  ovs_assert (strategy == MC_BROAD
              || strategy == MC_DEEP
              || strategy == MC_RANDOM);
  options->strategy = strategy;
}

/* Returns OPTION's random seed used by MC_RANDOM and
   MC_DROP_RANDOM. */
unsigned int
mc_options_get_seed (const struct mc_options *options)
{
  return options->seed;
}

/* Set OPTION's random seed used by MC_RANDOM and MC_DROP_RANDOM
   to SEED. */
void
mc_options_set_seed (struct mc_options *options, unsigned int seed)
{
  options->seed = seed;
}

/* Returns the maximum depth to which OPTIONS's search will
   descend.  The initial states are at depth 1, states produced
   as their mutations are at depth 2, and so on. */
int
mc_options_get_max_depth (const struct mc_options *options)
{
  return options->max_depth;
}

/* Sets the maximum depth to which OPTIONS's search will descend
   to MAX_DEPTH.  The initial states are at depth 1, states
   produced as their mutations are at depth 2, and so on. */
void
mc_options_set_max_depth (struct mc_options *options, int max_depth)
{
  options->max_depth = max_depth;
}

/* Returns the base-2 log of the number of bits in OPTIONS's hash
   table.  The hash table is used for dropping states that are
   probably duplicates: any state with a given hash value, as
   will only be processed once.  A return value of 0 indicates
   that the model checker will not discard duplicate states based
   on their hashes.

   The hash table is a power of 2 bits long, by default 2**20
   bits (128 kB).  Depending on how many states you expect the
   model checker to check, how much memory you're willing to let
   the hash table take up, and how worried you are about missing
   states due to hash collisions, you could make it larger or
   smaller.

   The "birthday paradox" points to a reasonable way to size your
   hash table.  If you expect the model checker to check about
   2**N states, then, assuming a perfect hash, you need a hash
   table of 2**(N+1) bits to have a 50% chance of seeing a hash
   collision, 2**(N+2) bits to have a 25% chance, and so on. */
int
mc_options_get_hash_bits (const struct mc_options *options)
{
  return options->hash_bits;
}

/* Sets the base-2 log of the number of bits in OPTIONS's hash
   table to HASH_BITS.  A HASH_BITS value of 0 requests that the
   model checker not discard duplicate states based on their
   hashes.  (This causes the model checker to never terminate in
   many cases.) */
void
mc_options_set_hash_bits (struct mc_options *options, int hash_bits)
{
  ovs_assert (hash_bits >= 0);
  options->hash_bits = MIN (hash_bits, CHAR_BIT * sizeof (unsigned int) - 1);
}

/* Returns the path set in OPTIONS by mc_options_set_follow_path.
   May be used only if the search strategy is MC_PATH. */
const struct mc_path *
mc_options_get_follow_path (const struct mc_options *options)
{
  ovs_assert (options->strategy == MC_PATH);
  return &options->follow_path;
}

/* Sets, in OPTIONS, the search algorithm to MC_PATH and the path
   to be the explicit path specified in FOLLOW_PATH. */
void
mc_options_set_follow_path (struct mc_options *options,
                            const struct mc_path *follow_path)
{
  ovs_assert (mc_path_get_length (follow_path) > 0);
  options->strategy = MC_PATH;
  mc_path_copy (&options->follow_path, follow_path);
}

/* Returns the maximum number of queued states in OPTIONS.  The
   default value is 10,000.  The primary reason to limit the
   number of queued states is to conserve memory, so if you can
   afford the memory and your model needs more room in the queue,
   you can raise the limit.  Conversely, if your models are large
   or memory is constrained, you can reduce the limit.

   Following the execution of the model checker, you can find out
   the maximum queue length during the run by calling
   mc_results_get_max_queue_length. */
int
mc_options_get_queue_limit (const struct mc_options *options)
{
  return options->queue_limit;
}

/* Sets the maximum number of queued states in OPTIONS to
   QUEUE_LIMIT.  */
void
mc_options_set_queue_limit (struct mc_options *options, int queue_limit)
{
  ovs_assert (queue_limit > 0);
  options->queue_limit = queue_limit;
}

/* Returns the queue limit strategy used by OPTIONS, that is,
   when a new state must be inserted into a full state queue is
   full, how the state to be dropped is chosen.  The choices are:

   - MC_DROP_NEWEST: Drop the newest state; that is, do not
     insert the new state into the queue at all.

   - MC_DROP_OLDEST: Drop the state that has been enqueued for
     the longest.

   - MC_DROP_RANDOM (the default): Drop a randomly selected state
     from the queue.  The standard C library's rand function
     selects the state to drop; you can control the seed passed
     to srand using mc_options_set_seed. */
enum mc_queue_limit_strategy
mc_options_get_queue_limit_strategy (const struct mc_options *options)
{
  return options->queue_limit_strategy;
}

/* Sets the queue limit strategy used by OPTIONS to STRATEGY.

   This setting has no effect unless the model being checked
   causes the state queue to overflow (see
   mc_options_get_queue_limit). */
void
mc_options_set_queue_limit_strategy (struct mc_options *options,
                                     enum mc_queue_limit_strategy strategy)
{
  ovs_assert (strategy == MC_DROP_NEWEST
              || strategy == MC_DROP_OLDEST
              || strategy == MC_DROP_RANDOM);
  options->queue_limit_strategy = strategy;
}

/* Returns OPTIONS's maximum number of unique states that the
   model checker will examine before terminating.  The default is
   INT_MAX. */
int
mc_options_get_max_unique_states (const struct mc_options *options)
{
  return options->max_unique_states;
}

/* Sets OPTIONS's maximum number of unique states that the model
   checker will examine before terminating to
   MAX_UNIQUE_STATE. */
void
mc_options_set_max_unique_states (struct mc_options *options,
                                  int max_unique_states)
{
  options->max_unique_states = max_unique_states;
}

/* Returns the maximum number of errors that OPTIONS will allow
   the model checker to encounter before terminating.  The
   default is 1. */
int
mc_options_get_max_errors (const struct mc_options *options)
{
  return options->max_errors;
}

/* Sets the maximum number of errors that OPTIONS will allow the
   model checker to encounter before terminating to
   MAX_ERRORS. */
void
mc_options_set_max_errors (struct mc_options *options, int max_errors)
{
  options->max_errors = max_errors;
}

/* Returns the maximum amount of time, in seconds, that OPTIONS will allow the
   model checker to consume before terminating.  The
   default of 0.0 means that time consumption is unlimited. */
double
mc_options_get_time_limit (const struct mc_options *options)
{
  return options->time_limit;
}

/* Sets the maximum amount of time, in seconds, that OPTIONS will
   allow the model checker to consume before terminating to
   TIME_LIMIT.  A value of 0.0 means that time consumption is
   unlimited; otherwise, the return value will be positive. */
void
mc_options_set_time_limit (struct mc_options *options, double time_limit)
{
  ovs_assert (time_limit >= 0.0);
  options->time_limit = time_limit;
}

/* Returns the level of verbosity for output messages specified
   by OPTIONS.  The default verbosity level is 1.

   A verbosity level of 0 inhibits all messages except for
   errors; a verbosity level of 1 also allows warnings; a
   verbosity level of 2 also causes a description of each state
   added to be output; a verbosity level of 3 also causes a
   description of each duplicate state to be output.  Verbosity
   levels less than 0 or greater than 3 are allowed but currently
   have no additional effect. */
int
mc_options_get_verbosity (const struct mc_options *options)
{
  return options->verbosity;
}

/* Sets the level of verbosity for output messages specified
   by OPTIONS to VERBOSITY. */
void
mc_options_set_verbosity (struct mc_options *options, int verbosity)
{
  options->verbosity = verbosity;
}

/* Returns the level of verbosity for failures specified by
   OPTIONS.  The default failure verbosity level is 2.

   The failure verbosity level has an effect only when an error
   is reported, and only when the failure verbosity level is
   higher than the regular verbosity level.  When this is the
   case, the model checker replays the error path at the higher
   verbosity level specified.  This has the effect of outputting
   an explicit, human-readable description of the sequence of
   operations that caused the error. */
int
mc_options_get_failure_verbosity (const struct mc_options *options)
{
  return options->failure_verbosity;
}

/* Sets the level of verbosity for failures specified by OPTIONS
   to FAILURE_VERBOSITY. */
void
mc_options_set_failure_verbosity (struct mc_options *options,
                                  int failure_verbosity)
{
  options->failure_verbosity = failure_verbosity;
}

/* Returns the output file used for messages printed by the model
   checker specified by OPTIONS.  The default is stdout. */
FILE *
mc_options_get_output_file (const struct mc_options *options)
{
  return options->output_file;
}

/* Sets the output file used for messages printed by the model
   checker specified by OPTIONS to OUTPUT_FILE.

   The model checker does not automatically close the specified
   output file.  If this is desired, the model checker's client
   must do so. */
void
mc_options_set_output_file (struct mc_options *options,
                            FILE *output_file)
{
  options->output_file = output_file;
}

/* Returns the number of microseconds between calls to the
   progress function specified by OPTIONS.   The default is
   250,000 (1/4 second).  A value of 0 disables progress
   reporting. */
int
mc_options_get_progress_usec (const struct mc_options *options)
{
  return options->progress_usec;
}

/* Sets the number of microseconds between calls to the progress
   function specified by OPTIONS to PROGRESS_USEC.  A value of 0
   disables progress reporting. */
void
mc_options_set_progress_usec (struct mc_options *options, int progress_usec)
{
  ovs_assert (progress_usec >= 0);
  options->progress_usec = progress_usec;
}

/* Returns the function called to report progress specified by
   OPTIONS.  The function used by default prints '.' to
   stderr. */
mc_progress_func *
mc_options_get_progress_func (const struct mc_options *options)
{
  return options->progress_func;
}

/* Sets the function called to report progress specified by
   OPTIONS to PROGRESS_FUNC.  A non-null function must be
   specified; to disable progress reporting, set the progress
   reporting interval to 0.

   PROGRESS_FUNC will be called zero or more times while the
   model checker's run is ongoing.  For these calls to the
   progress function, mc_results_get_stop_reason will return
   MC_CONTINUING.  It will also be called exactly once soon
   before mc_run returns, in which case
   mc_results_get_stop_reason will return a different value. */
void
mc_options_set_progress_func (struct mc_options *options,
                              mc_progress_func *progress_func)
{
  ovs_assert (options->progress_func != NULL);
  options->progress_func = progress_func;
}

/* Returns the auxiliary data set in OPTIONS by the client.  The
   default is a null pointer.

   This auxiliary data value can be retrieved by the
   client-specified functions in struct mc_class during a model
   checking run using mc_get_aux. */
void *
mc_options_get_aux (const struct mc_options *options)
{
  return options->aux;
}

/* Sets the auxiliary data in OPTIONS to AUX. */
void
mc_options_set_aux (struct mc_options *options, void *aux)
{
  options->aux = aux;
}

/* Options command-line parser. */

/* Prints a reference for the model checker command line options
   to stdout. */
void
mc_usage (void)
{
  fputs (
    "\nModel checker search algorithm options:\n"
    "  --strategy=STRATEGY  Basic search strategy.  One of:\n"
    "                         broad: breadth-first search (default)\n"
    "                         deep: depth-first search\n"
    "                         random: randomly ordered search\n"
    "  --path=#[,#]...      Fixes the exact search path to follow;\n"
    "                       mutually exclusive with --strategy\n"
    "  --max-depth=MAX      Limits search depth to MAX.  The initial\n"
    "                       states are at depth 1.\n"
    "  --hash-bits=BITS     Use 2**BITS size hash table to avoid\n"
    "                       duplicate states (0 will disable hashing)\n"
    "  --seed=SEED          Sets the random number seed\n"
    "\nModel checker queuing options:\n"
    "  --queue-limit=N      Limit queue to N states (default: 10000)\n"
    "  --queue-drop=TYPE    How to drop states when queue overflows:\n"
    "                         newest: drop most recently added state\n"
    "                         oldest: drop least recently added state\n"
    "                         random (default): drop a random state\n"
    "\nModel checker stop condition options:\n"
    "  --max-states=N       Stop after visiting N unique states\n"
    "  --max-errors=N       Stop after N errors (default: 1)\n"
    "  --time-limit=SECS    Stop after SECS seconds\n"
    "\nModel checker user interface options:\n"
    "  --progress=TYPE      Show progress according to TYPE.  One of:\n"
    "                         none: Do not output progress message\n"
    "                         dots (default): Output lines of dots\n"
    "                         fancy: Show a few stats\n"
    "                         verbose: Show all available stats\n"
    "  --verbosity=LEVEL    Verbosity level before an error (default: 1)\n"
    "  --failure-verbosity=LEVEL  Verbosity level for replaying failure\n"
    "                       cases (default: 2)\n",
    stdout);
}

/* Results of a model checking run. */
struct mc_results
  {
    /* Overall results. */
    enum mc_stop_reason stop_reason;    /* Why the run ended. */
    int unique_state_count;             /* Number of unique states checked. */
    int error_count;                    /* Number of errors found. */

    /* Depth statistics. */
    int max_depth_reached;              /* Max depth state examined. */
    unsigned long int depth_sum;        /* Sum of depths. */
    int n_depths;                       /* Number of depths in depth_sum. */

    /* If error_count > 0, path to the last error reported. */
    struct mc_path error_path;

    /* States dropped... */
    int duplicate_dropped_states;       /* ...as duplicates. */
    int off_path_dropped_states;        /* ...as off-path (MC_PATH only). */
    int depth_dropped_states;           /* ...due to excessive depth. */
    int queue_dropped_states;           /* ...due to queue overflow. */

    /* Queue statistics. */
    int queued_unprocessed_states;      /* Enqueued but never dequeued. */
    int max_queue_length;               /* Maximum queue length observed. */

    /* Timing. */
    struct timeval start;               /* Start of model checking run. */
    struct timeval end;                 /* End of model checking run. */
  };

/* Creates, initializes, and returns a new set of results. */
static struct mc_results *
mc_results_create (void)
{
  struct mc_results *results = xcalloc (1, sizeof (struct mc_results));
  results->stop_reason = MC_CONTINUING;
  gettimeofday (&results->start, NULL);
  return results;
}

/* Destroys RESULTS. */
void
mc_results_destroy (struct mc_results *results)
{
  if (results != NULL)
    {
      mc_path_destroy (&results->error_path);
      free (results);
    }
}

/* Returns RESULTS's reason that the model checking run
   terminated.  The possible reasons are:

   - MC_CONTINUING: The run is not actually yet complete.  This
     can only be returned before mc_run has returned, e.g. when
     the progress function set by mc_options_set_progress_func
     examines the run's results.

   - MC_SUCCESS: The run completed because the queue emptied.
     The entire state space might not have been explored due to a
     requested limit on maximum depth, hash collisions, etc.

   - MC_MAX_UNIQUE_STATES: The run completed because as many
     unique states have been checked as were requested (using
     mc_options_set_max_unique_states).

   - MC_MAX_ERROR_COUNT: The run completed because the maximum
     requested number of errors (by default, 1 error) was
     reached.

   - MC_END_OF_PATH: The run completed because the path specified
     with mc_options_set_follow_path was fully traversed.

   - MC_TIMEOUT: The run completed because the time limit set
     with mc_options_set_time_limit was exceeded.

   - MC_INTERRUPTED: The run completed because SIGINT was caught
     (typically, due to the user typing Ctrl+C). */
enum mc_stop_reason
mc_results_get_stop_reason (const struct mc_results *results)
{
  return results->stop_reason;
}

/* Returns the number of unique states checked specified by
   RESULTS. */
int
mc_results_get_unique_state_count (const struct mc_results *results)
{
  return results->unique_state_count;
}

/* Returns the number of errors found specified by RESULTS. */
int
mc_results_get_error_count (const struct mc_results *results)
{
  return results->error_count;
}

/* Returns the maximum depth reached during the model checker run
   represented by RESULTS.  The initial states are at depth 1,
   their child states at depth 2, and so on. */
int
mc_results_get_max_depth_reached (const struct mc_results *results)
{
  return results->max_depth_reached;
}

/* Returns the mean depth reached during the model checker run
   represented by RESULTS. */
double
mc_results_get_mean_depth_reached (const struct mc_results *results)
{
  return (results->n_depths == 0
          ? 0
          : (double) results->depth_sum / results->n_depths);
}

/* Returns the path traversed to obtain the last error
   encountered during the model checker run represented by
   RESULTS.  Returns a null pointer if the run did not report any
   errors. */
const struct mc_path *
mc_results_get_error_path (const struct mc_results *results)
{
  return results->error_count > 0 ? &results->error_path : NULL;
}

/* Returns the number of states dropped as duplicates (based on
   hash value) during the model checker run represented by
   RESULTS. */
int
mc_results_get_duplicate_dropped_states (const struct mc_results *results)
{
  return results->duplicate_dropped_states;
}

/* Returns the number of states dropped because they were off the
   path specified by mc_options_set_follow_path during the model
   checker run represented by RESULTS.  A nonzero value here
   indicates a missing call to mc_include_state in the
   client-supplied mutation function. */
int
mc_results_get_off_path_dropped_states (const struct mc_results *results)
{
  return results->off_path_dropped_states;
}

/* Returns the number of states dropped because their depth
   exceeded the maximum specified with mc_options_set_max_depth
   during the model checker run represented by RESULTS. */
int
mc_results_get_depth_dropped_states (const struct mc_results *results)
{
  return results->depth_dropped_states;
}

/* Returns the number of states dropped from the queue due to
   queue overflow during the model checker run represented by
   RESULTS. */
int
mc_results_get_queue_dropped_states (const struct mc_results *results)
{
  return results->queue_dropped_states;
}

/* Returns the number of states that were checked and enqueued
   but never dequeued and processed during the model checker run
   represented by RESULTS.  This is zero if the stop reason is
   MC_CONTINUING or MC_SUCCESS; otherwise, it is the number of
   states in the queue at the time that the checking run
   stopped. */
int
mc_results_get_queued_unprocessed_states (const struct mc_results *results)
{
  return results->queued_unprocessed_states;
}

/* Returns the maximum length of the queue during the model
   checker run represented by RESULTS.  If this is equal to the
   maximum queue length, then the queue (probably) overflowed
   during the run; otherwise, it did not overflow. */
int
mc_results_get_max_queue_length (const struct mc_results *results)
{
  return results->max_queue_length;
}

/* Returns the time at which the model checker run represented by
   RESULTS started. */
struct timeval
mc_results_get_start (const struct mc_results *results)
{
  return results->start;
}

/* Returns the time at which the model checker run represented by
   RESULTS ended.  (This function may not be called while the run
   is still ongoing.) */
struct timeval
mc_results_get_end (const struct mc_results *results)
{
  ovs_assert (results->stop_reason != MC_CONTINUING);
  return results->end;
}

/* Returns the number of seconds obtained by subtracting time Y
   from time X. */
static double
timeval_subtract (struct timeval x, struct timeval y)
{
  /* From libc.info. */
  double difference;

  /* Perform the carry for the later subtraction by updating Y. */
  if (x.tv_usec < y.tv_usec) {
    int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
    y.tv_usec -= 1000000 * nsec;
    y.tv_sec += nsec;
  }
  if (x.tv_usec - y.tv_usec > 1000000) {
    int nsec = (x.tv_usec - y.tv_usec) / 1000000;
    y.tv_usec += 1000000 * nsec;
    y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     `tv_usec' is certainly positive. */
  difference = (x.tv_sec - y.tv_sec) + (x.tv_usec - y.tv_usec) / 1000000.0;
  if (x.tv_sec < y.tv_sec)
    difference = -difference;
  return difference;
}


/* Returns the duration, in seconds, of the model checker run
   represented by RESULTS.  (This function may not be called
   while the run is still ongoing.) */
double
mc_results_get_duration (const struct mc_results *results)
{
  ovs_assert (results->stop_reason != MC_CONTINUING);
  return timeval_subtract (results->end, results->start);
}

/* Prints a description of RESULTS to stream F. */
void
mc_results_print (const struct mc_results *results, FILE *f)
{
  enum mc_stop_reason reason = mc_results_get_stop_reason (results);

  if (reason != MC_CONTINUING)
    fprintf (f, "Stopped by: %s\n",
             reason == MC_SUCCESS ? "state space exhaustion"
             : reason == MC_MAX_UNIQUE_STATES ? "reaching max unique states"
             : reason == MC_MAX_ERROR_COUNT ? "reaching max error count"
             : reason == MC_END_OF_PATH ? "reached end of specified path"
             : reason == MC_TIMEOUT ? "reaching time limit"
             : reason == MC_INTERRUPTED ? "user interruption"
             : "unknown reason");
  fprintf (f, "Errors found: %d\n\n", mc_results_get_error_count (results));

  fprintf (f, "Unique states checked: %d\n",
           mc_results_get_unique_state_count (results));
  fprintf (f, "Maximum depth reached: %d\n",
           mc_results_get_max_depth_reached (results));
  fprintf (f, "Mean depth reached: %.2f\n\n",
           mc_results_get_mean_depth_reached (results));

  fprintf (f, "Dropped duplicate states: %d\n",
           mc_results_get_duplicate_dropped_states (results));
  fprintf (f, "Dropped off-path states: %d\n",
           mc_results_get_off_path_dropped_states (results));
  fprintf (f, "Dropped too-deep states: %d\n",
           mc_results_get_depth_dropped_states (results));
  fprintf (f, "Dropped queue-overflow states: %d\n",
           mc_results_get_queue_dropped_states (results));
  fprintf (f, "Checked states still queued when stopped: %d\n",
           mc_results_get_queued_unprocessed_states (results));
  fprintf (f, "Maximum queue length reached: %d\n",
           mc_results_get_max_queue_length (results));

  if (reason != MC_CONTINUING)
    fprintf (f, "\nRuntime: %.2f seconds\n",
             mc_results_get_duration (results));
}

/* An active model checking run. */
struct mc
  {
    /* Related data structures. */
    const struct mc_class *class;
    struct mc_options *options;
    struct mc_results *results;

    /* Array of 2**(options->hash_bits) bits representing states
       already visited. */
    unsigned long int *hash;

    /* State queue. */
    struct mc_state **queue;            /* Array of pointers to states. */
    struct deque queue_deque;           /* Deque. */

    /* State currently being built by "init" or "mutate". */
    struct mc_path path;                /* Path to current state. */
    struct ds path_string;              /* Buffer for path_string function. */
    bool state_named;                   /* mc_name_operation called? */
    bool state_error;                   /* mc_error called? */

    /* Statistics for calling the progress function. */
    unsigned int progress;              /* Current progress value. */
    unsigned int next_progress;         /* Next value to call progress func. */
    unsigned int prev_progress;         /* Last value progress func called. */
    struct timeval prev_progress_time;  /* Last time progress func called. */

    /* Information for handling and restoring SIGINT. */
    bool interrupted;                   /* SIGINT received? */
    bool *saved_interrupted_ptr;        /* Saved value of interrupted_ptr. */
    void (*saved_sigint) (int);         /* Saved SIGINT handler. */
  };

/* A state in the queue. */
struct mc_state
  {
    struct mc_path path;                /* Path to this state. */
    void *data;                         /* Client-supplied data. */
  };

/* Points to the current struct mc's "interrupted" member. */
static bool *interrupted_ptr = NULL;

static const char *path_string (struct mc *);
static void free_state (const struct mc *, struct mc_state *);
static void stop (struct mc *, enum mc_stop_reason);
static struct mc_state *make_state (const struct mc *, void *);
static size_t random_queue_index (struct mc *);
static void enqueue_state (struct mc *, struct mc_state *);
static void do_error_state (struct mc *);
static void next_operation (struct mc *);
static bool is_off_path (const struct mc *);
static void sigint_handler (int signum);
static void init_mc (struct mc *,
                     const struct mc_class *, struct mc_options *);
static void finish_mc (struct mc *);

/* Runs the model checker on the client-specified CLASS with the
   client-specified OPTIONS.  OPTIONS may be a null pointer if
   the defaults are acceptable.  Destroys OPTIONS; use
   mc_options_clone if a copy is needed.

   Returns the results of the model checking run, which must be
   destroyed by the client with mc_results_destroy.

   To pass auxiliary data to the functions in CLASS, use
   mc_options_set_aux on OPTIONS, which may be retrieved from the
   CLASS functions using mc_get_aux. */
struct mc_results *
mc_run (const struct mc_class *class, struct mc_options *options)
{
  struct mc mc;

  init_mc (&mc, class, options);
  while (!deque_is_empty (&mc.queue_deque)
         && mc.results->stop_reason == MC_CONTINUING)
    {
      struct mc_state *state = mc.queue[deque_pop_front (&mc.queue_deque)];
      mc_path_copy (&mc.path, &state->path);
      mc_path_push (&mc.path, 0);
      class->mutate (&mc, state->data);
      free_state (&mc, state);
      if (mc.interrupted)
        stop (&mc, MC_INTERRUPTED);
    }
  finish_mc (&mc);

  return mc.results;
}

/* Tests whether the current operation is one that should be
   performed, checked, and enqueued.  If so, returns true.
   Otherwise, returns false and, unless checking is stopped,
   advances to the next state.  The caller should then advance
   to the next operation.

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
bool
mc_include_state (struct mc *mc)
{
  if (mc->results->stop_reason != MC_CONTINUING)
    return false;
  else if (is_off_path (mc))
    {
      next_operation (mc);
      return false;
    }
  else
    return true;
}

/* Tests whether HASH represents a state that has (probably)
   already been enqueued.  If not, returns false and marks HASH
   so that it will be treated as a duplicate in the future.  If
   so, returns true and advances to the next state.  The
   caller should then advance to the next operation.

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
bool
mc_discard_dup_state (struct mc *mc, unsigned int hash)
{
  if (!mc->state_error && mc->options->hash_bits > 0)
    {
      hash &= (1u << mc->options->hash_bits) - 1;
      if (bitmap_is_set (mc->hash, hash))
        {
          if (mc->options->verbosity > 2)
            fprintf (mc->options->output_file,
                     "    [%s] discard duplicate state\n", path_string (mc));
          mc->results->duplicate_dropped_states++;
          next_operation (mc);
          return true;
        }
      bitmap_set1 (mc->hash, hash);
    }
  return false;
}

/* Names the current state NAME, which may contain
   printf-style format specifications.  NAME should be a
   human-readable name for the current operation.

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
void
mc_name_operation (struct mc *mc, const char *name, ...)
{
  va_list args;

  va_start (args, name);
  mc_vname_operation (mc, name, args);
  va_end (args);
}

/* Names the current state NAME, which may contain
   printf-style format specifications, for which the
   corresponding arguments must be given in ARGS.  NAME should be
   a human-readable name for the current operation.

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
void
mc_vname_operation (struct mc *mc, const char *name, va_list args)
{
  if (mc->state_named && mc->options->verbosity > 0)
    fprintf (mc->options->output_file, "  [%s] warning: duplicate call "
             "to mc_name_operation (missing call to mc_add_state?)\n",
             path_string (mc));
  mc->state_named = true;

  if (mc->options->verbosity > 1)
    {
      fprintf (mc->options->output_file, "  [%s] ", path_string (mc));
      vfprintf (mc->options->output_file, name, args);
      putc ('\n', mc->options->output_file);
    }
}

/* Reports the given error MESSAGE for the current operation.
   The resulting state should still be passed to mc_add_state
   when all relevant error messages have been issued.  The state
   will not, however, be enqueued for later mutation of its own.

   By default, model checking stops after the first error
   encountered.

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
void
mc_error (struct mc *mc, const char *message, ...)
{
  va_list args;

  if (mc->results->stop_reason != MC_CONTINUING)
    return;

  if (mc->options->verbosity > 1)
    fputs ("    ", mc->options->output_file);
  fprintf (mc->options->output_file, "[%s] error: ",
           path_string (mc));
  va_start (args, message);
  vfprintf (mc->options->output_file, message, args);
  va_end (args);
  putc ('\n', mc->options->output_file);

  mc->state_error = true;
}

/* Enqueues DATA as the state corresponding to the current
   operation.  The operation should have been named with a call
   to mc_name_operation, and it should have been checked by the
   caller (who should have reported any errors with mc_error).

   This function should be called from the client-provided
   "mutate" function, according to the pattern explained in the
   big comment at the top of model-checker.h. */
void
mc_add_state (struct mc *mc, void *data)
{
  if (!mc->state_named && mc->options->verbosity > 0)
    fprintf (mc->options->output_file, "  [%s] warning: unnamed state\n",
             path_string (mc));

  if (mc->results->stop_reason != MC_CONTINUING)
    {
      /* Nothing to do. */
    }
  else if (mc->state_error)
    do_error_state (mc);
  else if (is_off_path (mc))
    mc->results->off_path_dropped_states++;
  else if (mc->path.length + 1 > mc->options->max_depth)
    mc->results->depth_dropped_states++;
  else
    {
      /* This is the common case. */
      mc->results->unique_state_count++;
      if (mc->results->unique_state_count >= mc->options->max_unique_states)
        stop (mc, MC_MAX_UNIQUE_STATES);
      enqueue_state (mc, make_state (mc, data));
      next_operation (mc);
      return;
    }

  mc->class->destroy (mc, data);
  next_operation (mc);
}

/* Returns the options that were passed to mc_run for model
   checker MC. */
const struct mc_options *
mc_get_options (const struct mc *mc)
{
  return mc->options;
}

/* Returns the current state of the results for model checker
   MC.  This function is appropriate for use from the progress
   function set by mc_options_set_progress_func.

   Not all of the results are meaningful before model checking
   completes. */
const struct mc_results *
mc_get_results (const struct mc *mc)
{
  return mc->results;
}

/* Returns the auxiliary data set on the options passed to mc_run
   with mc_options_set_aux. */
void *
mc_get_aux (const struct mc *mc)
{
  return mc_options_get_aux (mc_get_options (mc));
}

/* Expresses MC->path as a string and returns the string. */
static const char *
path_string (struct mc *mc)
{
  ds_clear (&mc->path_string);
  mc_path_to_string (&mc->path, &mc->path_string);
  return ds_cstr (&mc->path_string);
}

/* Frees STATE, including client data. */
static void
free_state (const struct mc *mc, struct mc_state *state)
{
  mc->class->destroy (mc, state->data);
  mc_path_destroy (&state->path);
  free (state);
}

/* Sets STOP_REASON as the reason that MC's processing stopped,
   unless MC is already stopped. */
static void
stop (struct mc *mc, enum mc_stop_reason stop_reason)
{
  if (mc->results->stop_reason == MC_CONTINUING)
    mc->results->stop_reason = stop_reason;
}

/* Creates and returns a new state whose path is copied from
   MC->path and whose data is specified by DATA. */
static struct mc_state *
make_state (const struct mc *mc, void *data)
{
  struct mc_state *new = xmalloc (sizeof *new);
  mc_path_init (&new->path);
  mc_path_copy (&new->path, &mc->path);
  new->data = data;
  return new;
}

/* Returns the index in MC->queue of a random element in the
   queue. */
static size_t
random_queue_index (struct mc *mc)
{
  ovs_assert (!deque_is_empty (&mc->queue_deque));
  return deque_front (&mc->queue_deque,
                      rand () % deque_count (&mc->queue_deque));
}

/* Adds NEW to MC's state queue, dropping a state if necessary
   due to overflow. */
static void
enqueue_state (struct mc *mc, struct mc_state *new)
{
  size_t idx;

  if (new->path.length > mc->results->max_depth_reached)
    mc->results->max_depth_reached = new->path.length;
  mc->results->depth_sum += new->path.length;
  mc->results->n_depths++;

  if (deque_count (&mc->queue_deque) < mc->options->queue_limit)
    {
      /* Add new state to queue. */
      if (deque_is_full (&mc->queue_deque))
        mc->queue = deque_expand (&mc->queue_deque,
                                   mc->queue, sizeof *mc->queue);
      switch (mc->options->strategy)
        {
        case MC_BROAD:
          idx = deque_push_back (&mc->queue_deque);
          break;
        case MC_DEEP:
          idx = deque_push_front (&mc->queue_deque);
          break;
        case MC_RANDOM:
          if (!deque_is_empty (&mc->queue_deque))
            {
              idx = random_queue_index (mc);
              mc->queue[deque_push_front (&mc->queue_deque)]
                = mc->queue[idx];
            }
          else
            idx = deque_push_front (&mc->queue_deque);
          break;
        case MC_PATH:
          ovs_assert (deque_is_empty (&mc->queue_deque));
          ovs_assert (!is_off_path (mc));
          idx = deque_push_back (&mc->queue_deque);
          if (mc->path.length
              >= mc_path_get_length (&mc->options->follow_path))
            stop (mc, MC_END_OF_PATH);
          break;
        default:
          OVS_NOT_REACHED ();
        }
      if (deque_count (&mc->queue_deque) > mc->results->max_queue_length)
        mc->results->max_queue_length = deque_count (&mc->queue_deque);
    }
  else
    {
      /* Queue has reached limit, so replace an existing
         state. */
      ovs_assert (mc->options->strategy != MC_PATH);
      ovs_assert (!deque_is_empty (&mc->queue_deque));
      mc->results->queue_dropped_states++;
      switch (mc->options->queue_limit_strategy)
        {
        case MC_DROP_NEWEST:
          free_state (mc, new);
          return;
        case MC_DROP_OLDEST:
          switch (mc->options->strategy)
            {
            case MC_BROAD:
              idx = deque_front (&mc->queue_deque, 0);
              break;
            case MC_DEEP:
              idx = deque_back (&mc->queue_deque, 0);
              break;
            case MC_RANDOM:
            case MC_PATH:
            default:
              OVS_NOT_REACHED ();
            }
          break;
        case MC_DROP_RANDOM:
          idx = random_queue_index (mc);
          break;
        default:
          OVS_NOT_REACHED ();
        }
      free_state (mc, mc->queue[idx]);
    }
  mc->queue[idx] = new;
}

/* Process an error state being added to MC. */
static void
do_error_state (struct mc *mc)
{
  mc->results->error_count++;
  if (mc->results->error_count >= mc->options->max_errors)
    stop (mc, MC_MAX_ERROR_COUNT);

  mc_path_copy (&mc->results->error_path, &mc->path);

  if (mc->options->failure_verbosity > mc->options->verbosity)
    {
      struct mc_options *path_options;

      fprintf (mc->options->output_file, "[%s] retracing error path:\n",
               path_string (mc));
      path_options = mc_options_clone (mc->options);
      mc_options_set_verbosity (path_options, mc->options->failure_verbosity);
      mc_options_set_failure_verbosity (path_options, 0);
      mc_options_set_follow_path (path_options, &mc->path);

      mc_results_destroy (mc_run (mc->class, path_options));

      putc ('\n', mc->options->output_file);
    }
}

/* Advances MC to start processing the operation following the
   current one. */
static void
next_operation (struct mc *mc)
{
  mc_path_push (&mc->path, mc_path_pop (&mc->path) + 1);
  mc->state_error = false;
  mc->state_named = false;

  if (++mc->progress >= mc->next_progress)
    {
      struct timeval now;
      double elapsed, delta;

      if (mc->results->stop_reason == MC_CONTINUING
          && !mc->options->progress_func (mc))
        stop (mc, MC_INTERRUPTED);

      gettimeofday (&now, NULL);

      if (mc->options->time_limit > 0.0
          && (timeval_subtract (now, mc->results->start)
              > mc->options->time_limit))
        stop (mc, MC_TIMEOUT);

      elapsed = timeval_subtract (now, mc->prev_progress_time);
      if (elapsed > 0.0)
        {
          /* Re-estimate the amount of progress to take
             progress_usec microseconds. */
          unsigned int progress = mc->progress - mc->prev_progress;
          double progress_sec = mc->options->progress_usec / 1000000.0;
          delta = progress / elapsed * progress_sec;
        }
      else
        {
          /* No measurable time at all elapsed during that amount
             of progress.  Try doubling the amount of progress
             required. */
          delta = (mc->progress - mc->prev_progress) * 2;
        }

      if (delta > 0.0 && delta + mc->progress + 1.0 < UINT_MAX)
        mc->next_progress = mc->progress + delta + 1.0;
      else
        mc->next_progress = mc->progress + (mc->progress - mc->prev_progress);

      mc->prev_progress = mc->progress;
      mc->prev_progress_time = now;
    }
}

/* Returns true if we're tracing an explicit path but the current
   operation produces a state off that path, false otherwise. */
static bool
is_off_path (const struct mc *mc)
{
  return (mc->options->strategy == MC_PATH
          && (mc_path_back (&mc->path)
              != mc_path_get_operation (&mc->options->follow_path,
                                        mc->path.length - 1)));
}

/* Handler for SIGINT. */
static void
sigint_handler (int signum OVS_UNUSED)
{
  /* Just mark the model checker as interrupted. */
  *interrupted_ptr = true;
}

/* Initializes MC as a model checker with the given CLASS and
   OPTIONS.  OPTIONS may be null to use the default options. */
static void
init_mc (struct mc *mc, const struct mc_class *class,
         struct mc_options *options)
{
  /* Validate and adjust OPTIONS. */
  if (options == NULL)
    options = mc_options_create ();
  ovs_assert (options->queue_limit_strategy != MC_DROP_OLDEST
              || options->strategy != MC_RANDOM);
  if (options->strategy == MC_PATH)
    {
      options->max_depth = INT_MAX;
      options->hash_bits = 0;
    }
  if (options->progress_usec == 0)
    {
      options->progress_func = null_progress;
      if (options->time_limit > 0.0)
        options->progress_usec = 250000;
    }

  /* Initialize MC. */
  mc->class = class;
  mc->options = options;
  mc->results = mc_results_create ();

  mc->hash = (mc->options->hash_bits > 0
              ? bitmap_allocate(1 << mc->options->hash_bits)
              : NULL);

  mc->queue = NULL;
  deque_init_null (&mc->queue_deque);

  mc_path_init (&mc->path);
  mc_path_push (&mc->path, 0);
  ds_init (&mc->path_string);
  mc->state_named = false;
  mc->state_error = false;

  mc->progress = 0;
  mc->next_progress = mc->options->progress_usec != 0 ? 100 : UINT_MAX;
  mc->prev_progress = 0;
  mc->prev_progress_time = mc->results->start;

  if (mc->options->strategy == MC_RANDOM
      || options->queue_limit_strategy == MC_DROP_RANDOM)
    srand (mc->options->seed);

  mc->interrupted = false;
  mc->saved_interrupted_ptr = interrupted_ptr;
  interrupted_ptr = &mc->interrupted;
  mc->saved_sigint = signal (SIGINT, sigint_handler);

  class->init (mc);
}

/* Complete the model checker run for MC. */
static void
finish_mc (struct mc *mc)
{
  /* Restore signal handlers. */
  signal (SIGINT, mc->saved_sigint);
  interrupted_ptr = mc->saved_interrupted_ptr;

  /* Mark the run complete. */
  stop (mc, MC_SUCCESS);
  gettimeofday (&mc->results->end, NULL);

  /* Empty the queue. */
  mc->results->queued_unprocessed_states = deque_count (&mc->queue_deque);
  while (!deque_is_empty (&mc->queue_deque))
    {
      struct mc_state *state = mc->queue[deque_pop_front (&mc->queue_deque)];
      free_state (mc, state);
    }

  /* Notify the progress function of completion. */
  mc->options->progress_func (mc);

  /* Free memory. */
  mc_path_destroy (&mc->path);
  ds_destroy (&mc->path_string);
  mc_options_destroy (mc->options);
  free (mc->queue);
  free (mc->hash);
}
