// command line option defaults

#define DFL_CIPHER	"AES-128-CBC"	// any "openssl -h" cipher command
#define DFL_IDENT	".ident"
#define DFL_NO_IDENT	".noident"	// pidentd compatible
#define DFL_OS		"UNIX"		// any RFC-1340 operating system token
#define DFL_PASSWD	"/etc/ident.key"// chmod o-rw; line #1 is passphrase
#define DFL_T_O		60U		// timeout must be >0; should be >29
#define DFL_USERNAME	"nobody"	// must be in passwd database

// controls where files are installed and how the prog IDs itself

#define PACKAGE		"authd"		// must match gettext MO filename
#define VERSION		"1.4.4"		// should match rpm.spec %{version}

#define CONTACT		"http://bugzilla.redhat.com/"

// reliability vs performance tuning; defaults fine for most busy servers

#define PROC_RETRY	10U		// how many scans of tcp* to do
#define PROC_SLEEP_US	500000UL	// microsecs of sleep between retries
#define PROC_SIZE	4U		// size of avg proc file (unit: BUFSIZ)

// you shouldn't need to change PROC_* macros unless you're debugging/testing

#define PROC_V4		"/proc/net/tcp"	// linux procfs: IPv4 version or NULL
#define PROC_V6		"/proc/net/tcp6"//           ... IPv6 version or NULL
#define PROC_MAX_LEN	256U		// max line length in tcp/tcp6
