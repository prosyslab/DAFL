# DAFL: Directed Grey-box Fuzzing guided by Data Dependency
<a href="https://goodtaeeun.github.io/assets/papers/sec23.pdf" target="_blank"><img src="https://goodtaeeun.github.io/assets/papers/sec23.png" align="right" width="250"></a>

## Introduction
DAFL is a directed grey-box fuzzer implemented on top of <a href="https://lcamtuf.coredump.cx/afl/" target="_blank">American Fuzzy Lop (AFL)</a>.
The goal of directed fuzzing is to guide the fuzzing process toward the target location and eventually expose possible bugs in the target location.
DAFL achieves this goal by leveraging the data dependency information of the target program.


## Two key concepts

The two key concepts of DAFL are:
1. **Semantic Relevance Scoring**: DAFL favors seeds that are more semantically relevant to the target location.
2. **Selective Coverage Feedback**: DAFL selectively receives coverage feedback only from the program locations relevant to the target.


To support these two concepts, DAFL takes two inputs: a data dependency graph and a list of instrumentation targets.

The data dependency graph is given in the form of a list of nodes and their proximity to the target location.
For instance, the node that corresponds to the target location is assigned the highest proximity value while the node that is the furthest away from the target location is assigned the proximity of 1.
Then, DAFL encodes a semantic relevance score to each program location based on the proximity value of the node that corresponds to the program location.
During the fuzzing process, DAFL computes the semantic relevance score of each seed as the sum of the semantic relevance scores of the program locations covered by the seed.
This score is used to favor seeds that are more semantically relevant to the target location.

The list of instrumentation targets is given in the form of a list of functions.
These functions are the functions that are covered by the inter-procedural data dependency graph.
By selectively instrumenting these functions, DAFL receives coverage feedback only from the program locations relevant to the target location.

These inputs are given to DAFL by setting the following environment variables:
```
export DAFL_DFG_SCORE=<path to the data dependency graph>
export DAFL_SELECTIVE_COV=<path to the list of instrumentation targets>
```



## How to use
DAFL is best used with its [framework](https://github.com/prosyslab/DAFL-artifact).
The framework provides an environment to run DAFL on a prepared set of target programs.
The framework also provides scripts that support preparing the environment, building the target programs, running the target programs, and evaluating the results. Thus, it is easy for users to refer to it and use it to run DAFL on their own target programs.

## Relevant links
- [DAFL paper](https://goodtaeeun.github.io/assets/papers/sec23.pdf)
- [DAFL talk](https://www.youtube.com/watch?v=BjtKhyzLtyo)
- [DAFL framework](https://github.com/prosyslab/DAFL-artifact)
- [Original AFL README](README_AFL.md)
