/* PSPP - a program for statistical analysis.
   Copyright (C) 2007, 2009, 2011, 2014, 2015 Free Software Foundation, Inc.

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

/* Implementation-level model checker.

   A model checker is a tool for software testing and
   verification that works by exploring all the possible states
   in a system and verifying their internal consistency.  A
   conventional model checker requires that the code in a system
   be translated into a specification language.  The model
   checker then verifies the specification, rather than the code.

   This is instead an implementation-level model checker, which
   does not require a separate specification.  Instead, the model
   checker requires writing a second implementation of the system
   being checked.  The second implementation can usually be made
   almost trivial in comparison to the one being checked, because
   it's usually acceptable for its performance to be
   comparatively poor, e.g. O(N^2) instead of O(lg N), and thus
   to use much simpler algorithms.

   For introduction to the implementation-level model checking
   approach used here, please refer to the following papers:

     Musuvathi, Park, Chou, Engler, Dill, "CMC: A Pragmatic
     Approach to Model Checking Real Code", Proceedings of the
     Fifth Symposium on Operating Systems Design and
     Implementation (OSDI), Dec 2002.
     http://sprout.stanford.edu/PAPERS/CMC-OSDI-2002/CMC-OSDI-2002.pdf

     Yang, Twohey, Engler, Musuvathi, "Using Model Checking to
     Find Serious File System Errors", Proceedings of the Sixth
     Symposium on Operating System Design and Implementation
     (OSDI), Dec 2004.
     http://www.stanford.edu/~engler/osdi04-fisc.pdf

     Yang, Twohey, Pfaff, Sar, Engler, "EXPLODE: A Lightweight,
     General Approach to Finding Serious Errors in Storage
     Systems", First Workshop on the Evaluation of Software
     Defect Detection Tools (BUGS), June 2005.
     http://benpfaff.org/papers/explode.pdf

   Use of a model checker is appropriate when the system being
   checked is difficult to test using handwritten tests.  This
   can be the case, for example, when the system has a
   complicated internal state that is difficult to reason about
   over a long series of operations.

   The implementation model checker works by putting a set of one
   of more initial states in a queue (and checking them for
   consistency).  Then the model checker removes a state from the
   queue and applies all possible operations of interest to it
   ("mutates" it), obtaining a set of zero or more child states
   (and checking each of them for consistency).  Each of these
   states is itself added to the queue.  The model checker
   continues dequeuing states and mutating and checking them
   until the queue is empty.

   In pseudo-code, the process looks like this:

     Q = { initial states }
     while Q is not empty:
       S = dequeue(Q)
       for each operation applicable to S do:
         T = operation(S)
         check(T)
         enqueue(Q, T)

   In many cases this process will never terminate, because every
   state has one or more child states.  For some systems this is
   unavoidable, but in others we can make the process finite by
   pursuing a few stratagems:

     1. Limit the maximum size of the system; for example, limit
        the number of rows and columns in the implementation of a
        table being checked.  The client of the model checker is
        responsible for implementing such limits.

     2. Avoid checking a single state more than one time.  This
        model checker provides assistance for this function by
        allowing the client to provide a hash of the system state.
        States with identical hashes will only be checked once
        during a single run.

   When a system cannot be made finite, or when a finite system
   is too large to check in a practical amount of time, the model
   checker provides multiple ways to limit the checking run:
   based on maximum depth, maximum unique states checked, maximum
   errors found (by default, 1), or maximum time used for
   checking.

   The client of the model checker must provide three functions
   via function pointers embedded into a "struct mc_class":

     1. void init (struct mc *mc);

        This function is called once at the beginning of a
        checking run.  It checks one or more initial states and
        adds them to the model checker's queue.  (If it does not
        add any states to the queue, then there is nothing to
        check.)

        Here's an outline for writing the init function:

          void
          init_foo (struct mc *mc)
          {
            struct foo *foo;

            mc_name_operation (mc, "initial state");
            foo = generate_initial_foo ();
            if (!state_is_consistent (foo))
              mc_error (mc, "inconsistent state");
            mc_add_state (mc, foo);
          }

     2. void mutate (struct mc *mc, const void *data);

        This function is called when a dequeued state is ready to
        be mutated.  For each operation that can be applied to
        the client-specified DATA, it applies that operation to a
        clone of the DATA, checks that the clone is consistent,
        and adds the clone to the model checker's queue.

        Here's an outline for writing the mutate function:

          void
          mutate_foo (struct mc *mc, void *state_)
          {
            struct foo *state = state_;

            for (...each operation...)
              if (mc_include_state (mc))
                {
                  struct foo *clone;

                  mc_name_operation (mc, "do operation %s", ...);
                  clone = clone_foo (state);
                  do_operation (clone);
                  if (!state_is_consistent (clone))
                    mc_error (mc, "inconsistent state");
                  if (mc_discard_dup_state (mc, hash_foo (clone)))
                    destroy_foo (clone);
                  else
                    mc_add_state (mc, clone);
                }
          }

        Notes on the above outline:

          - The call to mc_include_state allows currently
            uninteresting operations to be skipped.  It is not
            essential.

          - The call to mc_name_operation should give the current
            operation a human-readable name.  The name may
            include printf-style format specifications.

            When an error occurs, the model checker (by default)
            replays the sequence of operations performed to reach
            the error, printing the name of the operation at each
            step, which is often sufficient information in itself
            to debug the error.

            At higher levels of verbosity, the name is printed
            for each operation.

          - Operations should be performed on a copy of the data
            provided.  The data provided should not be destroyed
            or modified.

          - The call to mc_discard_dup_state is needed to discard
            (probably) duplicate states.  It is otherwise
            optional.

            To reduce the probability of collisions, use a
            high-quality hash function.  MD4 is a reasonable
            choice: it is fast but high-quality.  In one test,
            switching to MD4 from MD5 increased overall speed of
            model checking by 8% and actually reduced (!) the
            number of collisions.

            The hash value needs to include enough of the state
            to ensure that interesting states are not excluded,
            but it need not include the entire state.  For
            example, in many cases, the structure of complex data
            (metadata) is often much more important than the
            contents (data), so it may be reasonable to hash only
            the metadata.

            mc_discard_dup_state may be called before or after
            checking for consistency.  Calling it after checking
            may make checking a given number of unique states
            take longer, but it also ensures that all paths to a
            given state produce correct results.

          - The mc_error function reports errors.  It may be
            called as many times as desired to report each kind
            of inconsistency in a state.

          - The mc_add_state function adds the new state to the
            queue.  It should be called regardless of whether an
            error was reported, to indicate to the model checker
            that state processing has finished.

          - The mutation function should be deterministic, to
            make it possible to reliably reproduce errors.

     3. void destroy (struct mc *mc, void *data);

        This function is called to discard the client-specified
        DATA associated with a state.

   Numerous options are available for configuring the model
   checker.  The most important of these are:

     - Search algorithm:

       * Breadth-first search (the default): First try all the
         operations with depth 1, then those with depth 2, then
         those with depth 3, and so on.

         This search algorithm finds the least number of
         operations needed to trigger a given bug.

       * Depth-first search: Searches downward in the tree of
         states as fast as possible.  Good for finding bugs that
         require long sequences of operations to trigger.

       * Random-first search: Searches through the tree of
         states in random order.

       * Explicit path: Applies an explicitly specified sequence
         of operations.

     - Verbosity: By default, messages are printed only when an
       error is encountered, but you can cause the checker to
       print a message on every state transition.  This is most
       useful when the errors in your code cause segfaults or
       some other kind of sudden termination.

     - Treatment of errors: By default, when an error is
       encountered, the model checker recursively invokes itself
       with an increased verbosity level and configured to follow
       only the error path.  As long as the mutation function is
       deterministic, this quickly and concisely replays the
       error and describes the path followed to reach it in an
       easily human-readable manner.

     - Limits:

       * Maximum depth: You can limit the depth of the operations
         performed.  Most often useful with depth-first search.
         By default, depth is unlimited.

       * Maximum queue length: You can limit the number of states
         kept in the queue at any given time.  The main reason to
         do so is to limit memory consumption.  The default
         limit is 10,000 states.  Several strategies are
         available for choosing which state to drop when the
         queue overflows.

     - Stop conditions: based on maximum unique states checked,
       maximum errors found (by default, 1), or maximum time used
       for checking.

     - Progress: by default, the checker prints a '.' on stderr
       every .25 seconds, but you can substitute another progress
       function or disable progress printing.

   This model checker does not (yet) include two features
   described in the papers cited above: utility scoring
   heuristics to guide the search strategy and "choice points" to
   explore alternative cases.  The former feature is less
   interesting for this model checker, because the data
   structures we are thus far using it to model are much smaller
   than those discussed in the paper.  The latter feature we
   should implement at some point. */

#ifndef LIBPSPP_MODEL_CHECKER_H
#define LIBPSPP_MODEL_CHECKER_H 1

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

#include "compiler.h"

/* An active model checking run. */
struct mc;

/* Provided by each client of the model checker. */
struct mc_class
  {
    void (*init) (struct mc *);
    void (*mutate) (struct mc *, const void *);
    void (*destroy) (const struct mc *, void *);
  };

/* Results of a model checking run. */
struct mc_results;

/* Configuration for running the model checker. */
struct mc_options;

/* Primary external interface to model checker. */
struct mc_results *mc_run (const struct mc_class *, struct mc_options *);

/* Functions for use from client-supplied "init" and "mutate"
   functions. */
bool mc_include_state (struct mc *);
bool mc_discard_dup_state (struct mc *, unsigned int hash);
void mc_name_operation (struct mc *, const char *, ...)
    OVS_PRINTF_FORMAT (2, 3);
void mc_vname_operation (struct mc *, const char *, va_list)
    OVS_PRINTF_FORMAT (2, 0);
void mc_error (struct mc *, const char *, ...) OVS_PRINTF_FORMAT (2, 3);
void mc_add_state (struct mc *, void *data);

/* Functions for use from client-supplied "init", "mutate", and
   "destroy" functions. */
const struct mc_options *mc_get_options (const struct mc *);
const struct mc_results *mc_get_results (const struct mc *);
void *mc_get_aux (const struct mc *);

/* A path of operations through a model to arrive at some
   particular state. */
struct mc_path
  {
    int *ops;           /* Sequence of operations. */
    size_t length;      /* Number of operations. */
    size_t capacity;    /* Number of operations for which room is allocated. */
  };

void mc_path_init (struct mc_path *);
void mc_path_copy (struct mc_path *, const struct mc_path *);
void mc_path_push (struct mc_path *, int new_state);
int mc_path_pop (struct mc_path *);
int mc_path_back (const struct mc_path *);
void mc_path_destroy (struct mc_path *);

int mc_path_get_operation (const struct mc_path *, size_t index);
size_t mc_path_get_length (const struct mc_path *);

struct ds;
void mc_path_to_string (const struct mc_path *, struct ds *);

struct mc_options *mc_options_create (void);
struct mc_options *mc_options_clone (const struct mc_options *);
void mc_options_destroy (struct mc_options *);

/* Search strategy. */
enum mc_strategy
  {
    MC_BROAD,           /* Breadth-first search. */
    MC_DEEP,            /* Depth-first search. */
    MC_RANDOM,          /* Randomly ordered search. */
    MC_PATH             /* Follow one explicit path. */
  };

enum mc_strategy mc_options_get_strategy (const struct mc_options *);
void mc_options_set_strategy (struct mc_options *, enum mc_strategy);
unsigned int mc_options_get_seed (const struct mc_options *);
void mc_options_set_seed (struct mc_options *, unsigned int seed);
int mc_options_get_max_depth (const struct mc_options *);
void mc_options_set_max_depth (struct mc_options *, int max_depth);
int mc_options_get_hash_bits (const struct mc_options *);
void mc_options_set_hash_bits (struct mc_options *, int hash_bits);

const struct mc_path *mc_options_get_follow_path (const struct mc_options *);
void mc_options_set_follow_path (struct mc_options *, const struct mc_path *);

/* Strategy for dropped states from the queue when it
   overflows. */
enum mc_queue_limit_strategy
  {
    MC_DROP_NEWEST,     /* Don't enqueue the new state at all. */
    MC_DROP_OLDEST,     /* Drop the oldest state in the queue. */
    MC_DROP_RANDOM      /* Drop a random state from the queue. */
  };

int mc_options_get_queue_limit (const struct mc_options *);
void mc_options_set_queue_limit (struct mc_options *, int queue_limit);
enum mc_queue_limit_strategy mc_options_get_queue_limit_strategy (
  const struct mc_options *);
void mc_options_set_queue_limit_strategy (struct mc_options *,
                                          enum mc_queue_limit_strategy);

int mc_options_get_max_unique_states (const struct mc_options *);
void mc_options_set_max_unique_states (struct mc_options *,
                                       int max_unique_states);
int mc_options_get_max_errors (const struct mc_options *);
void mc_options_set_max_errors (struct mc_options *, int max_errors);
double mc_options_get_time_limit (const struct mc_options *);
void mc_options_set_time_limit (struct mc_options *, double time_limit);

int mc_options_get_verbosity (const struct mc_options *);
void mc_options_set_verbosity (struct mc_options *, int verbosity);
int mc_options_get_failure_verbosity (const struct mc_options *);
void mc_options_set_failure_verbosity (struct mc_options *,
                                       int failure_verbosity);
FILE *mc_options_get_output_file (const struct mc_options *);
void mc_options_set_output_file (struct mc_options *, FILE *);

typedef bool mc_progress_func (struct mc *);
mc_progress_func mc_progress_dots;
mc_progress_func mc_progress_fancy;
mc_progress_func mc_progress_verbose;

int mc_options_get_progress_usec (const struct mc_options *);
void mc_options_set_progress_usec (struct mc_options *, int progress_usec);
mc_progress_func *mc_options_get_progress_func (const struct mc_options *);
void mc_options_set_progress_func (struct mc_options *, mc_progress_func *);

void *mc_options_get_aux (const struct mc_options *);
void mc_options_set_aux (struct mc_options *, void *aux);


#define MC_OPTION_ENUMS                         \
    /* Search strategies. */                    \
    OPT_STRATEGY,                               \
    OPT_PATH,                                   \
    OPT_MAX_DEPTH,                              \
    OPT_HASH_BITS,                              \
    OPT_SEED,                                   \
                                                \
    /* Queuing. */                              \
    OPT_QUEUE_LIMIT,                            \
    OPT_QUEUE_DROP,                             \
                                                \
    /* Stop conditions. */                      \
    OPT_MAX_STATES,                             \
    OPT_MAX_ERRORS,                             \
    OPT_TIME_LIMIT,                             \
                                                \
    /* User interface. */                       \
    OPT_PROGRESS,                               \
    OPT_VERBOSITY,                              \
    OPT_FAILURE_VERBOSITY

#define MC_LONG_OPTIONS                                                 \
    {"strategy", required_argument, NULL, OPT_STRATEGY},                \
    {"max-depth", required_argument, NULL, OPT_MAX_DEPTH},              \
    {"hash-bits", required_argument, NULL, OPT_HASH_BITS},              \
    {"path", required_argument, NULL, OPT_PATH},                        \
    {"queue-limit", required_argument, NULL, OPT_QUEUE_LIMIT},          \
    {"queue-drop", required_argument, NULL, OPT_QUEUE_DROP},            \
    {"seed", required_argument, NULL, OPT_SEED},                        \
    {"max-states", required_argument, NULL, OPT_MAX_STATES},            \
    {"max-errors", required_argument, NULL, OPT_MAX_ERRORS},            \
    {"time-limit", required_argument, NULL, OPT_TIME_LIMIT},            \
    {"progress", required_argument, NULL, OPT_PROGRESS},                \
    {"verbosity", required_argument, NULL, OPT_VERBOSITY},              \
    {"failure-verbosity", required_argument, NULL, OPT_FAILURE_VERBOSITY}

#define MC_OPTION_HANDLERS(OPTIONS)                                     \
    case OPT_STRATEGY:                                                  \
      if (mc_options_get_strategy (OPTIONS) == MC_PATH)                 \
        ovs_fatal (0, "--strategy and --path are mutually exclusive");  \
                                                                        \
      if (!strcmp (optarg, "broad"))                                    \
        mc_options_set_strategy (OPTIONS, MC_BROAD);                    \
      else if (!strcmp (optarg, "deep"))                                \
        mc_options_set_strategy (OPTIONS, MC_DEEP);                     \
      else if (!strcmp (optarg, "random"))                              \
        mc_options_set_strategy (OPTIONS, MC_RANDOM);                   \
      else                                                              \
        ovs_fatal (0, "strategy must be `broad', `deep', or `random'"); \
      break;                                                            \
                                                                        \
    case OPT_MAX_DEPTH:                                                 \
      mc_options_set_max_depth (OPTIONS, atoi (optarg));                \
      break;                                                            \
                                                                        \
    case OPT_HASH_BITS:                                                 \
      {                                                                 \
        int requested_hash_bits = atoi (optarg);                        \
        int hash_bits;                                                  \
        mc_options_set_hash_bits (OPTIONS, requested_hash_bits);        \
        hash_bits = mc_options_get_hash_bits (OPTIONS);                 \
        if (hash_bits != requested_hash_bits)                           \
          ovs_fatal (0, "hash bits adjusted to %d.", hash_bits);        \
      }                                                                 \
      break;                                                            \
                                                                        \
    case OPT_PATH:                                                      \
      {                                                                 \
        struct mc_path path;                                            \
        char *op;                                                       \
                                                                        \
        if (mc_options_get_strategy (OPTIONS) != MC_BROAD)              \
          ovs_fatal (0, "--strategy and --path are mutually exclusive"); \
                                                                        \
        mc_path_init (&path);                                           \
        for (op = strtok (optarg, ":, \t"); op != NULL;                 \
             op = strtok (NULL, ":, \t"))                               \
          mc_path_push (&path, atoi (op));                              \
        if (mc_path_get_length (&path) == 0)                            \
          ovs_fatal (0, "at least one value must be specified on --path"); \
        mc_options_set_follow_path (OPTIONS, &path);                    \
        mc_path_destroy (&path);                                        \
      }                                                                 \
      break;                                                            \
                                                                        \
    case OPT_QUEUE_LIMIT:                                               \
      mc_options_set_queue_limit (OPTIONS, atoi (optarg));              \
      break;                                                            \
                                                                        \
    case OPT_QUEUE_DROP:                                                \
      if (!strcmp (optarg, "newest"))                                   \
        mc_options_set_queue_limit_strategy (OPTIONS, MC_DROP_NEWEST);  \
      else if (!strcmp (optarg, "oldest"))                              \
        mc_options_set_queue_limit_strategy (OPTIONS, MC_DROP_OLDEST);  \
      else if (!strcmp (optarg, "random"))                              \
        mc_options_set_queue_limit_strategy (OPTIONS, MC_DROP_RANDOM);  \
      else                                                              \
        ovs_fatal (0, "--queue-drop argument must be `newest' "         \
                   "`oldest' or `random'");                             \
      break;                                                            \
                                                                        \
    case OPT_SEED:                                                      \
      mc_options_set_seed (OPTIONS, atoi (optarg));                     \
      break;                                                            \
                                                                        \
    case OPT_MAX_STATES:                                                \
      mc_options_set_max_unique_states (OPTIONS, atoi (optarg));        \
      break;                                                            \
                                                                        \
    case OPT_MAX_ERRORS:                                                \
      mc_options_set_max_errors (OPTIONS, atoi (optarg));               \
      break;                                                            \
                                                                        \
    case OPT_TIME_LIMIT:                                                \
      mc_options_set_time_limit (OPTIONS, atof (optarg));               \
      break;                                                            \
                                                                        \
    case OPT_PROGRESS:                                                  \
      if (!strcmp (optarg, "none"))                                     \
        mc_options_set_progress_usec (OPTIONS, 0);                      \
      else if (!strcmp (optarg, "dots"))                                \
        mc_options_set_progress_func (OPTIONS, mc_progress_dots);       \
      else if (!strcmp (optarg, "fancy"))                               \
        mc_options_set_progress_func (OPTIONS, mc_progress_fancy);      \
      else if (!strcmp (optarg, "verbose"))                             \
        mc_options_set_progress_func (OPTIONS, mc_progress_verbose);    \
      break;                                                            \
                                                                        \
    case OPT_VERBOSITY:                                                 \
      mc_options_set_verbosity (OPTIONS, atoi (optarg));                \
      break;                                                            \
                                                                        \
    case OPT_FAILURE_VERBOSITY:                                         \
      mc_options_set_failure_verbosity (OPTIONS, atoi (optarg));        \
      break;

void mc_usage (void);

/* Reason that a model checking run terminated. */
enum mc_stop_reason
  {
    MC_CONTINUING,              /* Run has not yet terminated. */
    MC_SUCCESS,                 /* Queue emptied (ran out of states). */
    MC_MAX_UNIQUE_STATES,       /* Did requested number of unique states. */
    MC_MAX_ERROR_COUNT,         /* Too many errors. */
    MC_END_OF_PATH,             /* Processed requested path (MC_PATH only). */
    MC_TIMEOUT,                 /* Timeout. */
    MC_INTERRUPTED              /* Received SIGINT (Ctrl+C). */
  };

void mc_results_destroy (struct mc_results *);

enum mc_stop_reason mc_results_get_stop_reason (const struct mc_results *);
int mc_results_get_unique_state_count (const struct mc_results *);
int mc_results_get_error_count (const struct mc_results *);

int mc_results_get_max_depth_reached (const struct mc_results *);
double mc_results_get_mean_depth_reached (const struct mc_results *);

const struct mc_path *mc_results_get_error_path (const struct mc_results *);

int mc_results_get_duplicate_dropped_states (const struct mc_results *);
int mc_results_get_off_path_dropped_states (const struct mc_results *);
int mc_results_get_depth_dropped_states (const struct mc_results *);
int mc_results_get_queue_dropped_states (const struct mc_results *);
int mc_results_get_queued_unprocessed_states (const struct mc_results *);
int mc_results_get_max_queue_length (const struct mc_results *);

struct timeval mc_results_get_start (const struct mc_results *);
struct timeval mc_results_get_end (const struct mc_results *);
double mc_results_get_duration (const struct mc_results *);

void mc_results_print (const struct mc_results *, FILE *);

#endif /* libpspp/model-checker.h */
