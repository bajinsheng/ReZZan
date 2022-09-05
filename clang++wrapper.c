#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {
  cc_params = calloc((argc + 128), sizeof(u8*));
  cc_params[0] = "clang++";
  cc_params[cc_par_cnt++] = "-ldl";
  cc_params[cc_par_cnt++] = "-lrezzan";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "/opt/rezzan/rezzan.so";

  while (--argc) {
    u8* cur = *(++argv);
    cc_params[cc_par_cnt++] = cur;
  }
  cc_params[cc_par_cnt] = NULL;
}


/* Main entry point */

int main(int argc, char** argv) {
  edit_params(argc, argv);
  execvp(cc_params[0], (char**)cc_params);
  return 0;
}
