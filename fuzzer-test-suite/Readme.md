# Evaluation on fuzzer-test-suite (RQ4)

The script will automatica download, configure, and run the chosen fuzzer and subject.

## Run
```shell
./run_fuzzer-test-suite.sh <fuzzer> <target>
```
```
Usage: 
      fuzzer: {asan, rezzan, rezzan_lite}
      target: {c-ares-CVE-2016-5180, json-2017-02-12, libxml2-v2.9.2, openssl-1.0.1f, pcre2-10.00}
```
## Prerequisite
Please make sure ReZZan is installed and AFL (llvm mode) is compiled.

## Expected Results
The fuzzing campaign will automatically stop when a crash found, so the time to reach this bug can be observed from the AFL GUI.

## Example
```
./run_fuzzer-test-suite.sh rezzan c-ares-CVE-2016-5180
```
**Note**: There is no '/' after the `c-ares-CVE-2016-5180`