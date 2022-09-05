# Evaluation on Benchmark (RQ2)


The script will automatica download, configure, and run the chosen fuzzer and subject.

## Run
```shell
./run_benchmark.sh <fuzzer> <target>
```
```
Usage: 
      fuzzer: {asan, rezzan, rezzan_lite, native}
      target: {cxxfilt, file, jerryscript, mupdf, nm, objdump, libpng, size, sqlite, tcpdump}
```

## Prerequisite
Please make sure ReZZan is installed and AFL (llvm mode) is compiled.
Then executing this script to set up benchmark:
```
./setup_benchmark.sh
```

## Expected Results
After compilation, the execution speed and other AFL status will be shown in the terminal. The fuzzing campaign is expected to stop after 24 hours.

**Note**: To avoid unexpected environmental issues, please execute this command in a fresh docker instance. In other works, please avoid executing this command multiple times in the same docker instance.
