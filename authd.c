/*  authd, a lightweight IPv6/IPv4 inetd RFC 1413 ident protocol daemon
 *  Copyright 2004 by Red Hat, Inc.
 *
 *  THIS PROGRAM IS RELEASED UNDER THE GPL WITH THE ADDITIONAL EXEMPTION
 *  THAT COMPILING, LINKING, AND/OR USING OPENSSL IS ALLOWED.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 *
 *  Initial Author: Adrian Havill <havill@redhat.com>
 */

static const char RCSID[] = "$Revision: 1.18 $ $Date: 2004/07/28 16:04:05 $";

#include "config.h"

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>
#include <langinfo.h>
#include <libintl.h>
#include <netdb.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#if !defined NDEBUG
    #include <mcheck.h>
#endif

#define _(ascii_msgid) gettext(ascii_msgid)

static struct {
    int log_mask;
    int abrupt, help, hybrid, resolve, verbose, xerror; // longopt bool is pint
    bool debug, error, log, number, other, Version;
    char *codeset, *ident, *lang, *mapped, *os, *passwd, *username;
    char *Encrypt, *Noident;
    unsigned timeout, fn; unsigned long long multiquery;
} opt;

static void log_printf(int level, const char *s, ...) {
    if (opt.debug || level != LOG_DEBUG) {
        va_list ap;

        if (s == NULL || *s == '\0') {
            s = strerror(errno);
            assert(strchr(s, '%') == NULL);
        }
        if (opt.log) {
            va_start(ap, s);
            vsyslog(level, s, ap);
            va_end(ap);
        }
        va_start(ap, s);
        if (vfprintf(level == LOG_INFO ? stdout : stderr, s, ap) < 0) {
            perror(program_invocation_name);
            level = INT_MIN;
        }
        va_end(ap);
    }
    if (level <= LOG_ERR) exit(EXIT_FAILURE);
}
#define debug(...)        log_printf(LOG_DEBUG, __VA_ARGS__)
#define show(...)         log_printf(LOG_INFO, __VA_ARGS__)
#define log_notice(...)   log_printf(LOG_NOTICE, __VA_ARGS__)
#define log_warning(...)  log_printf(LOG_WARNING, __VA_ARGS__)
#define handle_error(...) log_printf(LOG_ERR, __VA_ARGS__)
 
#if !defined NDEBUG
static const void *const LAST_VA_ARG = "FIXME"; // debugging sentinel
#endif

static char *vstrdup(const char *s, ...) {
    va_list ap; char *dup;

    assert(s != LAST_VA_ARG);
    va_start(ap, s);
    while (s == NULL || *s == '\0') {
        s = va_arg(ap, const char *);
        assert(s != LAST_VA_ARG);
    }
    va_end(ap);
    if ((dup = strdup(s)) == NULL) handle_error(NULL);
    return dup;
}
#if !defined NDEBUG
    #define vstrdup(s, ...) vstrdup((s) ,##__VA_ARGS__ ,LAST_VA_ARG)
#endif

static void show_help(void) {
    show(_("%s [options]... [request]...\n"), program_invocation_short_name);
    show(_(" -d\t\t\tOutput debug messages\n"));
    show(_(" -E[cipher]\t\tEncrypt username using [%s]\n"), DFL_CIPHER);
    show(_(" -e\t\t\tSend UNKNOWN-ERROR for common error messages\n"));
    show(_(" -l[mask]\t\tLog to syslog, [mask] for priority levels\n"));
    show(_(" -m[reps]\t\tAllow at most [unlimited] requests/connection\n"));
    show(_(" -N[basename]\t\tHide users with ~/[%s] file\n"), DFL_NO_IDENT);
    show(_(" -n\t\t\tSend uid number instead of username\n"));
    show(_(" -o\t\t\tSend OTHER instead of the operating system\n"));
    show(_(" -t[secs]\t\tTimeout request after [%u] seconds\n"), DFL_T_O);
    show(_(" -V\t\t\tPrint program and version information\n"));
    show(_(" --abrupt\t\tDisconnect without displaying error msgs\n"));
    show(_(" --codeset=rfc1340\tSend [charset] if reply is not ASCII\n"));
    show(_(" --fn[=fields]\t\tUse [all] gecos fields instead of username\n"));
    show(_(" --hybrid\t\tUse hybrid notation (ex. ::127.0.0.1) for IPv6\n"));
    show(_(" --ident[=basename]\tHide users with no ~/[%s]\n"), DFL_IDENT);
    show(_(" --lang=lc\t\tLocalize messages, charsets, & time to [locale]\n"));
    show(_(" --mapped=ipv6\t\tMap addresses with same top 96 bits to IPv4\n"));
    show(_(" --os[=rfc1340]\t\tUse [uname], not %s, as OS name\n"), DFL_OS);
    show(_(" --passwd=pathname\tUse line 1 of [%s] for crypto\n"), DFL_PASSWD);
    show(_(" --resolve\t\tUse host and service names if available\n"));
    show(_(" --username[=login]\tUse [%s] as username\n"), DFL_USERNAME);
    show(_(" --verbose\t\tAdd real uid, addresses/ports, & timestamps\n"));
    show(_(" --xerror\t\tSend more helpful error messages for rare errors\n"));
}

static void show_version(void) {
    show("%s-%s:\n\t%s\n\t%s\n", PACKAGE, VERSION, RCSID, CONTACT);
}

static bool is_print_ascii(const char *s) {
    assert(s != NULL);
    while (*s != '\0')
        if (!isascii(*s) || iscntrl(*s)) return false;
        else s++;
    return true;
}

#define is_in_range(lo,x,hi) ((lo) <= (x) && (x) <= (hi))

static bool is_rfc1413_token(const char *s) {
    assert(s != NULL);
    if (!is_print_ascii(s) || strchr(s, ':') != NULL) return false;
    return is_in_range((size_t) 1, strlen(s), (size_t) 64);
}

static bool is_bad_strto(const char *s, const char *endptr) {
    if (errno == ERANGE || errno == EINVAL) return true;
    return endptr == s || (*endptr != '\0' && !isspace(*endptr));
}

static const int HEX_DIG = 2;           // two digits in 8-bit base 16 octet
static const size_t HEX_LEN_MAX = 32;   // strlen() of /proc/net/tcp6 address

static char *created_addr_hex(const unsigned char *addr, size_t addr_size) {
    char *addr_hex;
    size_t addr_hex_size = addr_size * HEX_DIG + sizeof '\0';

    if ((addr_hex = calloc(addr_hex_size, sizeof(char))) != NULL) {
        size_t z = addr_size; char *p = addr_hex;

        while (z != 0) {
            int n = snprintf(p, addr_hex_size, "%.*hhX", HEX_DIG, addr[--z]);

            assert(n >= 0 && (size_t) n < addr_hex_size);
            addr_hex_size -= (size_t) n; p += (size_t) n;
        }
    }
    return addr_hex;
}

static char *created_pton_hex(const char *prefix) {
    struct in6_addr addr; const size_t SIZE = sizeof(addr.s6_addr);

    assert(prefix != NULL);
    if (inet_pton(AF_INET6, prefix, &addr) <= 0) return NULL;
    return created_addr_hex((const void *) addr.s6_addr, SIZE);
}

static void create_opt(int argc, char *argv[]) {
    enum { PRE_FIRST_LONGOPT = UCHAR_MAX,       // no short opt value overlap
        CODESET_LONGOPT, IDENT_LONGOPT, FN_LONGOPT, LANG_LONGOPT,
        MAPPED_LONGOPT, OS_LONGOPT, PASSWD_LONGOPT, USERNAME_LONGOPT
    };
    int c, i;
    const char *const IPV4_HEX_0 = "00000000";
    const char *const S_FMT = _("%s: invalid argument to --%s: %s\n");
    const char *const C_FMT = _("%s: invalid argument to -%c: %s\n");
    const char *const SHORT_OPTS = "dE::ehl::m::N::not::V"; // pidentd compat
    const struct option LONG_OPTS[] = {
        { "abrupt",   no_argument,       &opt.abrupt,  true             },
        { "codeset",  required_argument, NULL,         CODESET_LONGOPT  },
        { "fn",       optional_argument, NULL,         FN_LONGOPT       },
        { "help",     no_argument,       NULL,         'h'              },
        { "hybrid",   no_argument,       &opt.hybrid,  true             },
        { "ident",    optional_argument, NULL,         IDENT_LONGOPT    },
        { "lang",     required_argument, NULL,         LANG_LONGOPT     },
        { "mapped",   required_argument, NULL,         MAPPED_LONGOPT   },
        { "os",       optional_argument, NULL,         OS_LONGOPT       },
        { "passwd",   required_argument, NULL,         PASSWD_LONGOPT   },
        { "resolve",  no_argument,       &opt.resolve, true             },
        { "usage",    no_argument,       NULL,         'h'              },
        { "username", optional_argument, NULL,         USERNAME_LONGOPT },
        { "verbose",  no_argument,       &opt.verbose, true             },
        { "xerror",   no_argument,       &opt.xerror,  true             },
        { 0,          0,                 0,            0                }
    };

    assert(argc > 0 && argv != NULL);
    memset(&opt, 0, sizeof(opt));
    opt.passwd = vstrdup(DFL_PASSWD);
    if ((opt.mapped = calloc(HEX_LEN_MAX + sizeof '\0', sizeof(char))) == NULL)
        handle_error(NULL);
    memset(opt.mapped, '0', HEX_LEN_MAX);
    opt.multiquery = 1;
    opt.timeout = UINT_MAX;
    while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, &i)) != -1) {
        switch (c) {
            struct utsname os;
            unsigned long lu; char *endptr, *lc;

            case 'd': opt.debug = true; break;
            case 'E':
                free(opt.Encrypt); opt.Encrypt = vstrdup(optarg, DFL_CIPHER);
                break;
            case 'e': opt.error = true; break;
            case 'h': opt.help = true; break;
            case 'l':
                if (optarg != NULL) {
                    lu = strtoul(optarg, &endptr, 0);
                    if (lu > UINT_MAX || is_bad_strto(optarg, endptr))
                        handle_error(C_FMT, *argv, c, optarg);
                    else opt.log_mask = (int) lu;
                    setlogmask(opt.log_mask);
                }
                opt.log = true;
                break;
            case 'm':
                if (optarg != NULL) {
                    opt.multiquery = strtoull(optarg, &endptr, 10);
                    if (is_bad_strto(optarg, endptr))
                        handle_error(C_FMT, *argv, c, optarg);
                }
                else opt.multiquery = ULLONG_MAX;
                break;
            case 'n': opt.number = true; break;
            case 'N':
                free(opt.Noident); opt.Noident = vstrdup(optarg, DFL_NO_IDENT);
                break;
            case 'o': opt.other = true; break;
            case 't':
                lu = optarg == NULL ? DFL_T_O : strtoul(optarg, &endptr, 10);
                if (lu > UINT_MAX || is_bad_strto(optarg, endptr))
                    handle_error(C_FMT, *argv, c, optarg);
                else if (lu < 30) {
                    log_notice(_("Timeout's too low; Raising to 30.\n"));
                    lu = 30;
                }
                else if (lu != 0 && !is_in_range(60, lu, 180)) 
                    log_notice(_("Timeout should be from 60..180 seconds.\n"));
                opt.timeout = (unsigned) lu;
                break;
            case 'V': opt.Version = true; break;
            case CODESET_LONGOPT:
                if (!is_rfc1413_token(optarg))
                    handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                free(opt.codeset); opt.codeset = vstrdup(optarg);
                break;
            case FN_LONGOPT:
                if (optarg != NULL) {
                    lu = strtoul(optarg, &endptr, 10);
                    if (lu > UINT_MAX || is_bad_strto(optarg, endptr))
                        handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                    else opt.fn = (unsigned) lu;
                }
                else opt.fn = UINT_MAX;
                break;
            case IDENT_LONGOPT:
                free(opt.ident); opt.ident = vstrdup(optarg, DFL_IDENT);
                break;
            case LANG_LONGOPT:
                lc = strlen(optarg) == 0 ? NULL : setlocale(LC_ALL, optarg);
                if (lc == NULL)
                    handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                else {
                    free(opt.lang); opt.lang = vstrdup(lc);
                    debug("LC_ALL = %s\n", opt.lang);
                }
                break;
            case MAPPED_LONGOPT:
                free(opt.mapped);
                if ((opt.mapped = created_pton_hex(optarg)) == NULL)
                    handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                if (strncmp(opt.mapped, IPV4_HEX_0, strlen(IPV4_HEX_0)) != 0)
                    log_notice(_("Mapped lower 32 bits not 0; ignoring.\n"));
                debug("prefix map    =%s/%s\n", IPV4_HEX_0, opt.mapped + 8);
                break;
            case OS_LONGOPT:
                if (optarg == NULL && uname(&os) != 0) handle_error(NULL);
                free(opt.os); opt.os = vstrdup(optarg, os.sysname);
                if (!is_rfc1413_token(opt.os))
                    handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                break;
            case PASSWD_LONGOPT:
                free(opt.passwd); opt.passwd = vstrdup(optarg, DFL_PASSWD);
                if (strlen(opt.passwd) == 0)
                    handle_error(S_FMT, *argv, LONG_OPTS[i].name, optarg);
                break;
            case USERNAME_LONGOPT:
                free(opt.username);
                opt.username = vstrdup(optarg, DFL_USERNAME);
                break;
            default:
                assert(0 == c); // GNU extensions ('\1' and ':') should be off
                break;
            case '?': exit(EXIT_FAILURE);
        }
    }
    if (optind < argc)
        opt.timeout = 0;        // don't get client input if request(s) in cmd
}

static const char *const DELIM = ",: \t\r\n\v\f";

static unsigned long long get_tok_ullong(char *s, unsigned base) {
    unsigned long long ull = ULLONG_MAX;

    assert(base <= 36);
    if ((s = strtok(s, DELIM)) != NULL) {
        char *endptr;

        ull = strtoull(s, &endptr, (int) base);
        if ((errno == ERANGE && ull == ULLONG_MAX) || is_bad_strto(s, endptr))
            errno = EINVAL;
    }
    else errno = EINVAL;
    return ull;
}


static unsigned long get_tok_uint(char *s, unsigned base) {
    unsigned long ul = ULONG_MAX;

    assert(base <= 36);
    if ((s = strtok(s, DELIM)) != NULL) {
        char *endptr;

        ul = strtoul(s, &endptr, (int) base);
        if (ul > UINT_MAX || is_bad_strto(s, endptr))
            errno = EINVAL;
    }
    else errno = EINVAL;
    return ul;
}

static long get_tok_int(char *s, unsigned base) {

    long l = LONG_MAX;

    assert(base <= 36);
    if ((s = strtok(s, DELIM)) != NULL) {
        char *endptr;

        l = strtol(s, &endptr, (int) base);
        if (l > INT_MAX || is_bad_strto(s, endptr))
            errno = EINVAL;
    }
    else errno = EINVAL;
    return l;
}


static void destroy_opt(void) {
    free(opt.codeset); free(opt.Encrypt); free(opt.ident); free(opt.lang);
    free(opt.Noident); free(opt.os); free(opt.passwd); free(opt.mapped);
    free(opt.username);
    memset(&opt, 0, sizeof(opt));
}

typedef struct {
    unsigned long lport, rport;
    char *laddr, *raddr;
} request_t;

typedef int (*getsockaddr_t)(int, struct sockaddr *, socklen_t *);

static char *created_connected_addr(int sockfd, getsockaddr_t getXXXXname) {
    struct sockaddr_storage name; socklen_t namelen = sizeof(name);
    char *addr_hex = NULL;

    if (getXXXXname(sockfd, (struct sockaddr *) &name, &namelen) == 0) {
        size_t addr_size = 0;
        const unsigned char *addr = NULL; 

        switch (name.ss_family) {
            struct sockaddr_in *sin; struct sockaddr_in6 *sin6;

        case AF_INET:
            sin = (struct sockaddr_in *) &name;
            addr_size = sizeof(sin->sin_addr.s_addr);
            addr = (unsigned char *) &sin->sin_addr.s_addr;
            break;
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) &name;
            addr_size = sizeof(sin6->sin6_addr.s6_addr);
            addr = (unsigned char *) sin6->sin6_addr.s6_addr;
            break;
        default:
            errno = EAFNOSUPPORT;
        }
        addr_hex = created_addr_hex(addr, addr_size);
    }
    else if (errno == ENOTSOCK)
        errno = 0;      // no error if invoked from cmdline
    return addr_hex;
}

static request_t created_request(int argc, char *argv[]) {
    request_t in;
    char *line = NULL; size_t n = 0;

    assert(argv != NULL && argc >= 1);
    if (optind >= argc) {
        if (fflush_unlocked(stdout) == EOF) handle_error(NULL);
        in.laddr = created_connected_addr(STDIN_FILENO, getsockname);
        in.raddr = created_connected_addr(STDIN_FILENO, getpeername);
        if (opt.timeout != UINT_MAX)
            alarm(opt.timeout);
        if (getline(&line, &n, stdin) == (ssize_t) -1) {
            if (feof_unlocked(stdin)) {
                free(line);
                exit(EXIT_SUCCESS);
            }
            assert(ferror(stdin));
            handle_error(NULL);
        }
        alarm(0);
    }
    else {
        line = vstrdup(argv[(size_t) optind++]);
        in.laddr = in.raddr = NULL;
    }
    in.lport = get_tok_uint(line, 10); in.rport = get_tok_uint(NULL, 10);
    debug("local_address =%s:%04lX\n", in.laddr, in.lport);
    debug("rem_address   =%s:%04lX\n", in.raddr, in.rport);
    free(line);
    return in;
}

static char *created_hostname(const char *node) {
    char *s;
    struct addrinfo *res, hints = { .ai_flags = AI_CANONNAME };

    assert(node != NULL && *node != '\0');
    if (opt.resolve && getaddrinfo(node, NULL, &hints, &res) == 0) {
        s = vstrdup(res->ai_canonname, node); freeaddrinfo(res);
    }
    else s = vstrdup(node);
    return s;
}

static const unsigned long PORT_MIN = 1, PORT_MAX = 65535;

static char *created_servicename(unsigned long port) {
    char *s;
    const char *const PROTO = "tcp", *const PORT_FMT = "%lu";
    const int NS_PORT = (int) htons((uint16_t) port);
    struct servent *res = opt.resolve ? getservbyport(NS_PORT, PROTO) : NULL;

    assert(is_in_range(PORT_MIN, port, PORT_MAX));
    if (res == NULL || res->s_name == NULL || *res->s_name == '\0') {
        if (asprintf(&s, PORT_FMT, port) < 0) handle_error(NULL);
    }
    else s = vstrdup(res->s_name);
    return s;
}

static char *get_created_tok_addr(const char *peer_addr_hex) {
    const char *const IPV6_0 = ":0000", *const IPV6_0_RUN = "::";
    const size_t IPV6_SIZE_MAX = INET6_ADDRSTRLEN + sizeof '\0';
    const size_t IPV6_0_RUN_LEN = strlen(IPV6_0_RUN);
    char *addr = calloc(sizeof ':' + IPV6_SIZE_MAX, sizeof(char));
    char *addr_hex, *p = addr, *q, *zero = NULL; size_t zero_n = 0;

    if (addr != NULL) {
        if ((addr_hex = strtok(NULL, DELIM)) != NULL) {
            size_t z = strlen(addr_hex); const bool IS_IPV6 = z > 8;
            bool is_16_bits = true;

            if (peer_addr_hex != NULL) {
                char peer_128[HEX_LEN_MAX + sizeof '\0'];
                char host_128[HEX_LEN_MAX + sizeof '\0'];

                assert(opt.mapped != NULL);
                strcpy(peer_128, opt.mapped); strcpy(host_128, opt.mapped);

                /*
                   If mapping IPV4 to IPV6 space is enabled,
                   take only last 4 numbers of IPV6
                */
                if(opt.mapped[0]) {
                  strncpy(host_128, addr_hex+z-8, 8);
                  strncpy(peer_128, peer_addr_hex, 8);
                } else {
                  strncpy(host_128, addr_hex, z);
                  strncpy(peer_128, peer_addr_hex, strlen(peer_addr_hex));
                }

                if (strcmp(peer_128, host_128) != 0) return addr;
            }
            // hex addr must have even number of digits
            if ((int) z & 1) {
                errno = EINVAL; return NULL;
            }
            while (z > 1) {
                unsigned long ul; char *endptr;
                const bool IS_IPV4 = (opt.hybrid && z < 9) || !IS_IPV6;

                addr_hex[z] = '\0'; z -= HEX_DIG;
                ul = strtoul(addr_hex + z, &endptr, 16);
                if (is_bad_strto(addr_hex + z, endptr)) {
                    errno = EINVAL; return NULL;
                }
	        if ((!IS_IPV4 || 6 == z) && is_16_bits)
                    *p++ = ':';
                if (IS_IPV4)
                    p += sprintf(p, "%lu", ul);
                else p += sprintf(p, "%.*lX", HEX_DIG, ul);
                if (IS_IPV4 && z != 0)
                    *p++ = '.';
                is_16_bits = !is_16_bits;
            }
        }
        // compress 16-bit runs of zeros
        for (p = strstr(addr, IPV6_0); p != NULL; p = strstr(q, IPV6_0)) {
            size_t count = 0; const size_t IPV6_0_LEN = strlen(IPV6_0);

            for (q = p; strncmp(q, IPV6_0, IPV6_0_LEN) == 0; q += IPV6_0_LEN)
                count += IPV6_0_LEN;
            if (count > zero_n) {
                zero_n = count; zero = p;
            }
        }
        if (zero_n >= IPV6_0_RUN_LEN) {
            memcpy(zero, IPV6_0_RUN, IPV6_0_RUN_LEN);
            zero += IPV6_0_RUN_LEN; zero_n -= IPV6_0_RUN_LEN;
            if (zero[zero_n] == ':')
                zero_n++;
            memmove(zero, zero + zero_n, strlen(zero + zero_n) + 1);
        }
        // compress four digit hex sequences by removing leading zeros
        while ((zero = strstr(addr, ":0")) != NULL)
            if (strchr(++zero, ':') == NULL) break;
            else memmove(zero, zero + 1, strlen(zero));
        if (addr[1] != ':')
            memmove(addr, addr + 1, IPV6_SIZE_MAX);  // rm ':' prefix
    }
    return addr;
}

static bool is_regular_file(const char *dir, const char *name) {
    bool is_existing = false;

    assert(dir != NULL);
    if (name != NULL) {
        struct stat st;

        if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            char *s;
            const char *const PATHNAME_FMT = "%s/%s";

            if (*name != '\0') {
                if (asprintf(&s, PATHNAME_FMT, dir, name) < 0) return false;
                is_existing = stat(s, &st) == 0 && S_ISREG(st.st_mode);
                free(s);
            }
            else errno = EISDIR;
        }
        else errno = ENOTDIR;
        if (errno == ENOENT)
            errno = 0;  // don't report X-ERRNO-%d
    }
    return is_existing;
}

typedef struct {
    bool error;
    unsigned lport, rport; char *os, *enc, *s;
} reply_t;

static const size_t USERID_MAX_LEN = 512; // as per RFC1413 <octet-string>
static const char *const TEXT_READ_MODE = "r"; // passphrase, /proc plaintext

static bool get_info(reply_t *out, request_t in, const char *tcpname) {
    //unsigned long lport, rport, uid, status; FILE *stream;
    unsigned long lport, rport, status; FILE *stream;
    long uid;
    const unsigned long ESTABLISHED = 0x01;
    unsigned lineno = 0;
    char *laddr = NULL, *raddr = NULL;
    bool is_port_pair_found = false;

    char *created_verbose(const char *name, unsigned long id) {
        size_t n; time_t tod;
        char *s, when[USERID_MAX_LEN], *host1, *port1, *host2, *port2;
        const char *const UTC_FMT = "%FT%TZ", *const TZ_FMT = "(%a %EX %z/%Z)";
        const char *const VERBOSE_FMT = "%s:%lu,%s,%s|%s,%s|%s";

        if (time(&tod) == (time_t) -1) handle_error(NULL);
        n = strftime(when, sizeof(when), UTC_FMT, gmtime(&tod));
        strftime(when + n, sizeof(when) - n, TZ_FMT, localtime(&tod));
        host1 = created_hostname(laddr); port1 = created_servicename(lport);
        host2 = created_hostname(raddr); port2 = created_servicename(rport);
        asprintf(&s, VERBOSE_FMT, name, id, when, host1, port1, host2, port2);
        free(host1); free(port1); free(host2); free(port2);
        return s;
    }

    assert(out != NULL);
    if (tcpname == NULL) return false;
    if ((stream = fopen(tcpname, TEXT_READ_MODE)) == NULL) {
        // some systems won't have tcp6 (and rarely, plain IPv4 tcp) files in
        // /proc/net. The absence of either file isn't an error; although
        // the lack of both prevents authd from looking up anything
        if (errno == ENOENT) {
            if (opt.log) log_notice("%s: %s\n", tcpname, strerror(errno));
            errno = 0;
        }
        else out->error = true;
    }
    else for (;;) {
        unsigned long sl, inode;
        uid_t euid;
        char line[PROC_MAX_LEN], tmp[PROC_MAX_LEN];

        // FIXME: setting the buffer to be larger than normal is done to
        // lessen (but not eliminate) the chance of the proc file changing
        // while in the middle of reading it
        if (0 == lineno) {
            const size_t SIZE = (size_t) (BUFSIZ * PROC_SIZE);

            if (setvbuf(stream, NULL, _IOFBF, SIZE) != 0) {
                out->error = true; break;
            }
        }
        if (fgets_unlocked(line, (int) PROC_MAX_LEN, stream) == NULL) {
            if (ferror_unlocked(stream))
                out->error = true;
            assert(feof(stream));
            break;
        }
        else lineno++;
        // first line of /proc/net/tcp* is a header that looks similar to:
        //    sl local rem st tx rx tr tm->when retrnsmt   uid  timeout inode
        if (1 == lineno) continue;
        // sample line from tcp (tcp6 just has a bigger ip address):
        //    0: 00000000:800B 00000000:0000 0A 0000:0000 00:0000 0000 0000 ...
        sl = get_tok_uint(strcpy(tmp, line), 10); // sl (base 10 uint)
        laddr = get_created_tok_addr(in.laddr);   // local (little endian hex)
        lport = get_tok_uint(NULL, 16);           // ... local port
        raddr = get_created_tok_addr(in.raddr);   // remote (little endian hex)
        rport = get_tok_uint(NULL, 16);           // ... remote port
        status = get_tok_uint(NULL, 16);          // status (01 = ESTABLISHED)
        (void) get_tok_uint(NULL, 16);            // tx_queue
        (void) get_tok_uint(NULL, 16);            // rx_queue
        (void) get_tok_uint(NULL, 16);            // tr (boolean)
        (void) get_tok_ullong(NULL, 16);            // tm->when (unit: jiffies)
        strtok(NULL, DELIM);                      // retrnsmt
        //uid = get_tok_uint(NULL, 10);             // uid (base 10 uint)
        uid = get_tok_int(NULL, 10);             // uid (base 10 int)
        strtok(NULL, DELIM);                      // timeout
        inode = get_tok_uint(NULL, 10);           // inode (base 10 uint)
        if (errno == EINVAL) {
            // format of /proc/net/tcp* has changed or it's a bogus file
            debug("%s:%u: %s", tcpname, lineno, line);  // XXX: NL terminated?
            out->error = true; errno = 0;
            out->s = opt.xerror ? vstrdup("X-PROC") : NULL; break;
        }
        else if (errno != 0) {
            // most likely an out-of-memory error
            out->error = true; break;
        }
        else if (*laddr == '\0' || *raddr == '\0') {
            // host address doesn't match peer address, so skip it
            free(laddr); free(raddr); laddr = raddr = NULL; continue;
        }
        else euid = (uid_t) uid;
        if (lport == in.lport && rport == in.rport && status == ESTABLISHED) {
            struct passwd *pwd = getpwuid(euid);

            is_port_pair_found = true;
            debug("%-14s=sl:%lu uid:%lu inode:%lu\n", tcpname, sl, uid, inode);
            if (opt.username != NULL) {
                if ((pwd = getpwnam(opt.username)) == NULL) {
                    out->error = true;
                    out->s = opt.xerror ? vstrdup("X-NAME") : NULL; break;
                }
                else euid = pwd->pw_uid;
            }
            if (pwd == NULL) { // passwd db doesn't have uid in /proc/net/tcp*
                out->error = true;
                out->s = opt.xerror ? vstrdup("X-UID") : NULL; break;
            }
            else {
                bool hidden = opt.ident != NULL;

                if (is_regular_file(pwd->pw_dir, opt.ident))
                    hidden = false;
                if (is_regular_file(pwd->pw_dir, opt.Noident))
                    hidden = true;
                if (errno) {
                    out->error = true;
                    out->s = opt.xerror ? vstrdup("X-FILE") : NULL;
                    break;
                }
                else if (hidden) {
                    out->error = true; out->s = vstrdup("HIDDEN-USER"); break;
                }
                out->s = vstrdup(pwd->pw_name);
                if (opt.number) {
                    const char *const UID_FMT = "%lu";

                    free(out->s);
                    if (asprintf(&out->s, UID_FMT, (unsigned long) euid) < 0) {
                        out->error = true; break;
                    }
                }
                if (opt.fn != 0 && *pwd->pw_gecos != '\0') {
                    char *s = vstrdup(pwd->pw_gecos);
                    size_t n = 0;

                    // gecos field usually just has 1 field, the full name--
                    // but sometimes the user's office, office phone and home
                    // phone will be in csv format
                    for (unsigned u = 0; u < opt.fn && s[n] != '\0'; u++, n++)
                        n += strcspn(s + n, ",");
                    s[--n] = '\0';
                    if (opt.number) {
                        n = strcspn(s, ",");
                        memmove(s, s + n, strlen(s + n) + 1);
                        n = strlen(out->s) + strlen(s);
                        if ((out->s = realloc(out->s, ++n)) == NULL) {
                            out->error = true; break;
                        }
                        strcat(out->s, s); free(s);
                    }
                    else { free(out->s); out->s = s; }
                }
            }
            if (opt.verbose && !out->error) {
                char *brief = out->s;

                if ((out->s = created_verbose(brief, uid)) == NULL)
                    out->error = true;
                else free(brief);
            }
            break;
        }
        else { free(laddr); free(raddr); laddr = raddr = NULL; }
    }
    free(laddr); free(raddr);
    if (stream != NULL && fclose(stream) == EOF) {
        out->error = true; out->s = NULL;
    }
    return is_port_pair_found;
}

typedef struct {
    const EVP_CIPHER *cipher; BIO *writer; BUF_MEM *buffer;
    unsigned char *key, *iv, salt[PKCS5_SALT_LEN];
} crypto_t;

static bool initialize_crypto(crypto_t *x, const char *filename) {
    struct stat file;
    bool is_initialized = false;

    assert(filename != NULL && x != NULL);
    if (stat(filename, &file) == 0) {
        FILE *stream; ssize_t len;
        const EVP_MD *const HASH = EVP_sha256();   // openssl compat: enc -pass
        const size_t KEY_SIZE = EVP_CIPHER_key_length(x->cipher);
        const size_t IV_SIZE = EVP_CIPHER_iv_length(x->cipher);
        char *pass = NULL; size_t z = 0;

        if (!S_ISREG(file.st_mode)) return false;       // no dirs, devs, etc.
        if  (file.st_mode & (S_IROTH | S_IWOTH)) return false;  // no ------rw-
        if ((x->key = malloc(KEY_SIZE)) == NULL) return false;
        if ((x->iv = malloc(IV_SIZE)) == NULL) return false;
        if ((stream = fopen(filename, TEXT_READ_MODE)) == NULL) return false;
        if ((len = getline(&pass, &z, stream)) == (ssize_t) -1) return false;
        if (fclose(stream) == EOF) return false;
        if (len > 0 && pass[(size_t) (len - 1)] == '\n')
            pass[(size_t) --len] = '\0';
        if (RAND_bytes(x->salt, sizeof(x->salt)) <= 0) return false;
        EVP_BytesToKey(x->cipher, HASH, x->salt, (const unsigned char*)pass, len, 1, x->key, x->iv);
        memset(pass, 0, len);                           // XXX: crypto erase
        free(pass);
        is_initialized = true;
        if (opt.debug) {
            char line[80] = { '\0' }, *p = line;
            int n; size_t size = sizeof(line);

            n = snprintf(p, size, "salt[%2zu bytes]=", sizeof(x->salt));
            assert(n >= 0);
            for (z = 0; z < sizeof(x->salt) && n < (int) size; z++) {
                p += n; size -= n;
                n = snprintf(p, size, "%.*hhX", CHAR_BIT / 4, x->salt[z]);
                assert(n >= 0);
            }
            debug("%s\n", line); p = line; size = sizeof(line);
            n = snprintf(p, size, "key[%4d bits]=", (int) KEY_SIZE * CHAR_BIT);
            assert(n >= 0);
            for (z = 0; z < KEY_SIZE && n < (int) size; z++) {
                p += n; size -= n;
                n = snprintf(p, size, "%.*hhX", CHAR_BIT / 4, x->key[z]);
                assert(n >= 0);
            }
            debug("%s\n", line); p = line; size = sizeof(line);
            n = snprintf(p, size, "iv[%5d bits]=", (int) IV_SIZE * CHAR_BIT);
            assert(n >= 0);
            for (z = 0; z < IV_SIZE && n < (int) size; z++) {
                p += n; size -= n;
                n = snprintf(p, size, "%.*hhX", CHAR_BIT / 4, x->iv[z]);
                assert(n >= 0);
            }
            debug("%s\n", line);
            memset(line, 0, sizeof(line));              // XXX: crypto erase
        }
    }
    return is_initialized;
}

static char *created_ciphertext_b64(const char *s) {
    BIO *encoder; char *b64;
    const char *const MAGIC = "Salted__";       // openssl compat: enc -salt
    const char *const NL = "\n";                // is strcat()ed to plaintext
    crypto_t x = { .cipher = NULL };

    assert(s != NULL);
    OpenSSL_add_all_ciphers();
    if ((x.cipher = EVP_get_cipherbyname(opt.Encrypt)) == NULL) return NULL;
    debug("cipher name   =%s\n", EVP_CIPHER_name(x.cipher));
    debug("cipher block  =%d bytes\n", EVP_CIPHER_block_size(x.cipher));
    switch (EVP_CIPHER_mode(x.cipher)) {
    case EVP_CIPH_ECB_MODE: debug("cipher mode   =%s\n", "ECB"); break;
    case EVP_CIPH_CBC_MODE: debug("cipher mode   =%s\n", "CBC"); break;
    case EVP_CIPH_CFB_MODE: debug("cipher mode   =%s\n", "CFB"); break;
    case EVP_CIPH_OFB_MODE: debug("cipher mode   =%s\n", "OFB"); break;
    case EVP_CIPH_STREAM_CIPHER: debug("cipher mode   =%s\n", "stream");
    }
    if (!initialize_crypto(&x, opt.passwd)) return NULL;
    if ((encoder = BIO_new(BIO_s_mem())) == NULL) return NULL;
    else x.writer = encoder;
    if ((encoder = BIO_new(BIO_f_base64())) == NULL) return NULL;
    else {
        BIO_set_flags(encoder, BIO_FLAGS_BASE64_NO_NL);
        x.writer = BIO_push(encoder, x.writer);
        if (BIO_write(x.writer, MAGIC, strlen(MAGIC)) <= 0) return NULL;
        if (BIO_write(x.writer, x.salt, sizeof(x.salt)) <= 0) return NULL;
    }
    if ((encoder = BIO_new(BIO_f_cipher())) == NULL) return NULL;
    else {
        BIO_set_cipher(encoder, x.cipher, x.key, x.iv, true);
        x.writer = BIO_push(encoder, x.writer);
    }
    if (BIO_write(x.writer, s, strlen(s)) <= 0) return NULL;
    if (BIO_write(x.writer, NL, strlen(NL)) <= 0) return NULL;
    if (BIO_flush(x.writer) <= 0) return NULL;
    BIO_get_mem_ptr(x.writer, &x.buffer);
    if ((b64 = calloc(x.buffer->length + 3, sizeof(char))) != NULL) {
        b64[0] = '[';                   // pidentd compat: base64 in brackets
        memcpy(b64 + 1, x.buffer->data, x.buffer->length);
        b64[x.buffer->length + 1] = ']';
    }
    BIO_free_all(x.writer); EVP_cleanup();
    free(x.key); free(x.iv);
    memset(&x, 0, sizeof(x));                           // XXX: crypto erase
    return b64;
}

static reply_t created_reply(request_t in) {
    reply_t out = { .lport = 0, .rport = 0 };
    bool is_invalid_port = false;
    unsigned attempts = 0;

    out.os = vstrdup(opt.other ? "OTHER" : opt.os, DFL_OS);
    out.enc = vstrdup(opt.codeset, nl_langinfo(CODESET), "X-UNKNOWN");
    if (!is_in_range(PORT_MIN, in.lport, PORT_MAX)) {
        in.lport = 0; is_invalid_port = true; errno = 0;
    }
    if (!is_in_range(PORT_MIN, in.rport, PORT_MAX)) {
        in.rport = 0; is_invalid_port = true; errno = 0;
    }
    out.lport = (unsigned) in.lport; out.rport = (unsigned) in.rport;
    if (is_invalid_port) {
        out.s = vstrdup("INVALID-PORT"); out.error = true;
    }
    // FIXME: because the /proc/net/tcp*'s updated asyncronously, it's possible
    // to miss reading a pair when reading syncronously (even with a locked
    // read & a large enough buffer). To lessen the chance of a false negative,
    // inefficiently & unreliably re-read proc more than once if not found.
    else for (;;) {
        // TODO: port pair more likely to be IPv4 than IPv6,
        // so scan IPv4 first for better performance; should be configurable
        if (get_info(&out, in, PROC_V4) || get_info(&out, in, PROC_V6)) break;
        else if (attempts++ < PROC_RETRY) {
            if (usleep(PROC_SLEEP_US) == -1) handle_error(NULL);
            continue;
        }
        out.error = true; errno = 0; out.s = vstrdup("NO-USER"); break;
    }
    if (!out.error && opt.Encrypt != NULL) {
        char *encrypted = created_ciphertext_b64(out.s);

        memset(out.s, 0, strlen(out.s));                // XXX: crypto erase
        free(out.s);
        if (encrypted == NULL) {
            int n;
            char msg[USERID_MAX_LEN], *p = msg;
            unsigned long code;
            size_t size = USERID_MAX_LEN;

            out.error = true;
            if (opt.xerror) {
                n = snprintf(p, size, "%s", "X-CRYPTO");
                assert(n >= 0);
                do if ((code = ERR_get_error()) != 0) {
                    p += n; size = (size_t) n > size ? 0 : size - n;
                    n = snprintf(p, size, "-%08lX", code);
                    assert(n >= 0);
                } while (code != 0 && (size_t) n < size);
                out.s = vstrdup(msg);
            }
            else out.s = NULL;
        }
        else out.s = encrypted;
    }
    // RFC1413: when the info field isn't usable as-is, set OS to OTHER
    if (opt.fn != 0 || opt.verbose || opt.number || opt.Encrypt != NULL) {
        free(out.os); out.os = vstrdup("OTHER");
    }
    return out;
}

static void send_reply(reply_t out) {
    char *s; int n; const char *fmt;
    // RFC 1413 says servers shouldn't use unnecessary space, but mimic
    // existing servers' behavior so inflexible clients work
    const char *const GOOD_FMT = "%u , %u : USERID : %s%.0s :%s\r\n";
    const char *const GOOD_NONASCII_FMT = "%u , %u : USERID : %s , %s :%s\r\n";
    const char *const BAD_FMT = "%u , %u : ERROR :%.0s%.0s%s%.0d\r\n";

    if (out.s == NULL || (opt.error && *out.s != 'X')) {
        out.s = "UNKNOWN-ERROR"; out.error = true;
    }
    if (strlen(out.s) > USERID_MAX_LEN || strpbrk(out.s, "\r\n") != NULL) {
        out.error = true; out.s = opt.xerror ? "X-RFC1413" : NULL;
    }
    if (out.error) {
        fmt = BAD_FMT;
        if (opt.log && errno != 0) log_warning(NULL);
        if (opt.abrupt) goto abrupt;
        if (opt.xerror && errno != 0 && *out.s != 'X')
            out.s = "X-ERRNO-";
    }
    else fmt = is_print_ascii(out.s) ? GOOD_FMT : GOOD_NONASCII_FMT;
    n = asprintf(&s, fmt, out.lport, out.rport, out.os, out.enc, out.s, errno);
    if (n < 0) handle_error(NULL);
    if (fputs_unlocked(s, stdout) == EOF) handle_error(NULL);
    else free(s);
abrupt:
    if (out.error) exit(EXIT_FAILURE); // must exit to clean alloc res
}

static void destroy_reply(reply_t *out) {
    assert(out != NULL && !out->error);
    free(out->os); free(out->enc); free(out->s); memset(out, 0, sizeof(*out));
}

static void destroy_request(request_t *in) {
    free(in->laddr); free(in->raddr); memset(in, 0, sizeof(*in));
}

static void catch_signal(int which) {
    _Exit(which == SIGALRM ? EXIT_SUCCESS : EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
#   if !defined NDEBUG
    mtrace();
#   endif
    if (setlocale(LC_ALL, "") == NULL) abort();
    errno = 0;			/* not an error for some locale files to
				   be missing */
    if (signal(SIGALRM, catch_signal) == SIG_ERR) abort();
    if (textdomain(PACKAGE) == NULL) handle_error(NULL);
    if (bindtextdomain(PACKAGE, NULL) == NULL) handle_error(NULL);
    openlog(PACKAGE, LOG_PID, LOG_DAEMON);
    create_opt(argc, argv);
    atexit(destroy_opt);
    if (opt.help) show_help();
    else if (opt.Version) show_version();
    else while (opt.multiquery-- != 0 && (opt.timeout != 0 || optind < argc)) {
        request_t in = created_request(argc, argv);
        reply_t out = created_reply(in);

        destroy_request(&in);
        send_reply(out);
        destroy_reply(&out);
    } 
    return EXIT_SUCCESS;
}
