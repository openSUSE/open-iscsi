#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef DEBUG
#define UIP_DEBUG(args...)  fprintf(stdout, args); fflush(stdout)
#else
#endif

#endif
