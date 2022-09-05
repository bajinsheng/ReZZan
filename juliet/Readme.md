# Evaluation on Juliet Test Suite (RQ1)

The script will automatica download, configure, and run the test suite.

## Run
```
./run_juliet.sh
```

## Prerequisite
Please make sure ReZZan is installed.

## Expected Results
The final results will be shown on the terminal when all done, like this:
```
--------------------------------------------------------------------------
Passed number in bad test cases:
      CWE  total  Asan  ReZZan  ReZZan_lite
0  CWE121   2860  2856    2860         2380
1  CWE122   3246  3198    3246         2724
2  CWE124    928   928     925          925
3  CWE126    630   619     630          630
4  CWE127    928   928     880          880
5  CWE416    392   392     392          392


Passed number in good test cases:
      CWE  total  Asan  ReZZan  ReZZan_lite
0  CWE121   2860  2860    2860         2860
1  CWE122   3246  3246    3246         3246
2  CWE124    928   928     928          928
3  CWE126    630   630     630          630
4  CWE127    928   928     928          928
5  CWE416    392   392     392          392
```

The `results` folder stores details of each test case. 1 represents the fuzzer detects a crash on corresponding test case.

## Example
**Bad test case**: In file `CWE121_Stack_Based_Buffer_Overflow_s01_bad.csv `, the **1** represents that Asan, ReZZan, and ReZZan_lite can detect the bug in test case `CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01`. **1** is expected as bugs exist.
|  target   | Asan  |  ReZZan   | ReZZan_lite  | 
|  ----  | ----  |  ----  | ----  |  
| CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01  | 1 | 1  | 1 |

**Good test case**: In file `CWE121_Stack_Based_Buffer_Overflow_s01_good.csv `, **0** represents Asan, ReZZan, and ReZZan_lite cannot detect any bug in test case `CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01`. **0** is expected as no bug exists.
|  target   | Asan  |  ReZZan   | ReZZan_lite  | 
|  ----  | ----  |  ----  | ----  |  
| CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01  | 0 | 0  | 0 |
