# authd: a RFC 1413 ident protocol daemon

* * *

1.  FEATURES
    *   written in C; small and fast
    *   two operation modes:
        1.  server via inetd/xinetd
        2.  script/interactive via command line arguments
    *   supports IPv6 and IPv4
    *   pidentd option compatibility
    *   easy to use openssl compatible strong symmetric encryption
    *   many privacy and anonymizing options
    *   works well even with broken clients
    *   internationalized log and help messages
    *   free software licensed under the GPL. This program is released under the GPL with the additional exemption that compiling, linking, and/or using OpenSSL is allowed.
2.  REQUIREMENTS & SETUP
    1.  Building  
        Although authd was built and tested on Red Hat Linux 9, Red Hat Enterprise Linux and Fedora Core 1 & 2, it will probably compile on any recent 2003/2004-era GNU/Linux distro with openssl and recent versions of the GNU tool chain (compiler + make) and GNU C library.

        authd does not require autoconf. If needed, change any defaults by editing the <samp>config.h</samp> file. To build, simply run "<kbd>make</kbd>"

    2.  Installing  
        "<kbd>make install</kbd>" will install "<samp>in.authd</samp>" and any translations in "<samp>/usr/local/sbin</samp>" and "<samp>/usr/local/locale</samp>" respectively, so you'll need to set the <kbd>make</kbd> variable <var>prefix</var> if you want the files to go somewhere else than "<samp>/usr/local</samp>". It will install as the filename "<samp>in.authd</samp>" to reflect that it is intended to run as a inetd/xinetd hosted server; in other words, server input/output is connected to stdin and stdout.

        If you're using encryption, put a one line pass phrase in the file "<samp>/etc/ident.key</samp>" (or another place if you change the default location via a server option), making sure the file is readable by the authd process and NOT readable/writable by others ("<kbd>chmod o-rw</kbd>"). **If the permissions are not set correctly, authd will refuse to encrypt.**

    3.  Running  
        authd should be able to read <samp>/proc/net/tcp</samp> and/or <samp>/proc/net/tcp6</samp> to actually match users to ports-- although it will run without these files.

        A sample xinetd configuration file has been provided; copying <kbd>xinetd.conf.auth</kbd> to <kbd>/etc/xinetd.d</kbd> should work for Red Hat distributions. Be sure to make any changes needed to the default values and path as needed then restart/reload the xinetd daemon to use it.

        All of the options available can be seen with the "<kbd>-h</kbd>" option. Some notes on some of the less obvious options and parameters:

        *   <kbd>--abrupt</kbd>  
            If an error occurs after the client has sent the port pair, just drop the connection rather than tell the client (allowed by RFC 1413). authd may do this anyway for certain errors that prevent it from sending a reply (I/O error or an out of memory situation). "<kbd>--abrupt</kbd>" overrides "<kbd>-e</kbd>" and "<kbd>--xerror</kbd>".
        *   <kbd>-E</kbd>[<var>cipher</var>]  
            Any symmetric block/stream encryption method supported by the installed openssl can be used as a parameter. To see a list of available <var>cipher</var>s, use "<kbd>openssl enc -h</kbd>"
        *   <kbd>-l</kbd>[<var>mask</var>]  
            An optional base 10, base 8 (prefix with "<kbd>0</kbd>"), or base 16 (prefix with "<kbd>0x</kbd>") bit mask of system log priority levels that you wish to log. For example, an <var>mask</var> of 17<small><sub>8</sub></small> ("<kbd>-l017</kbd>") only logs messages of priority error or higher.  

        *   <kbd>--fn</kbd>[<kbd>=</kbd><var>uint</var>]  
            Sends the full-name/"finger" info rather than the username. Some systems contain additional fields of information after the full name of a person, such as the office, office phone number and home phone, separated by commas. To display only the first field, specify "<kbd>1</kbd>". To specify up to two fields, specify "<kbd>2</kbd>"... and so on.

            If the "<kbd>-n</kbd>" option is also specified, then the numeric user id will be followed by the 2nd up to <var>uint</var> fields providing that <var>uint</var> is greater than two.

        *   <kbd>--hybrid</kbd>  
            Only applies to IPv6 addresses activated with the "--verbose" option. When used, the bottom 32 bits of the address with be displayed in the traditional IPv4 format of four dot separated base 10 numbers rather than the IPv6 style of eight 16-bit colon separated hex pairs.
        *   <kbd>--mapped=</kbd><var>ipv6</var>  
            Allows IPv6 addresses whose first 96 bits (in other words, everything except for the last 32 bits) are <var>ipv6</var> to match IPv4 addresses which are identical to the bottom 32-bits of the IPv6 address. Useful for IPv6/IPv4 multi-interface environments where IPv4 addresses on different interfaces are mapped to IPv6 addresses. _It does not match IPv4 "<samp>localhost</samp>" (<samp>127.0.0.1</samp>) with IPv6's equivalent (<samp>::1</samp>)._
        *   <kbd>--os</kbd>[<kbd>=</kbd><var>rfc1340</var>]  
            Without an argument, it will display the same value returned by the "<kbd>uname</kbd>" command as the operating system, rather than "UNIX". You may wish to do this if the username returned (perhaps from pam talking to a Windows server) does not make sense within a traditional UNIX or Linux system.
        *   <kbd>--resolve</kbd>  
            Only applies to addresses and ports activated with the "--verbose" option. Causes <samp>in.authd</samp> to resolve addresses using nameservers, and replace service port numbers with their names, when available. _Resolving addresses slows the server down._
        *   <kbd>--username</kbd>[<kbd>=</kbd><var>login</var>]  
            Causes authd to report the username <var>login</var> for all valid established tcp connections, regardless of the actual user. <var>login</var> must point to a valid entry in the password database. If used in conjunction with "<kbd>-n</kbd>", the uid of the <var>login</var> will be returned. It will _not_ change the uid number provided with the "<kbd>--verbose</kbd>" option. "<kbd>--username</kbd>" is useful for providing the actual user on single user workstations or servers that have changed their original associated uids to effective ones. It is also useful for masking the true username for privacy purposes (in this case authd is running as a dummy placebo server).
        *   <kbd>--verbose</kbd>  
            Adds the following information after the username or full name (depending on the option selected), separated by commas:
            *   true userid number  
                Different from "<kbd>-n</kbd>" which is affected by "<kbd>--username</kbd>".
            *   time stamp  
                Date and time is provided in ASCII ISO 8601 UTC/Zulu (aka Greenwich Median, or GMT) time. The day of week and time in the authd's local timezone using the locale's format and encoding are also provided in parentheses.
            *   local address and port  
                Port is separated from the address by a vertical bar, "local" is from the perspective of the authd server.
            *   remote address and port  
                Port is separated from the address by a vertical bar, "remote" is from the perspective of the authd server.The authd daemon will not read any input from stdin if port pairs are specified as parameters. Also, only the first port pair will be processed unless the "<kbd>-m</kbd>" option is specified.
    4.  Testing
        1.  Run "<kbd>netstat -A inet -n</kbd>" and find an established tcp connection.
        2.  Input the two ports prefixed with colons as single command line argument (no whitespace unless the entire pair is enclosed in quotes for the command line parser), in the same order, separated by a comma. Example:

            <samp>$ <kbd>/usr/sbin/in.inetd 33201,6667</kbd></samp>

        3.  Execute "<kbd>telnet localhost auth</kbd>" and type the two ports separated by a comma. _The two ports selected must have a foreign address of <samp>localhost</samp>, or <samp>127.0.0.1</samp> as well as a matching local address._ If they do not, a <samp>NO-USER</samp> error will be returned.
3.  DIFFERENCES FROM PIDENTD 3.0.18
    *   no config file  
        There is no "<samp>/etc/ident.conf</samp>", as all the options you need for a simple inet super daemon based server can be easily passed from the command line
    *   no special crypto tools  
        Key generation requires no special tools; a plain text pass phrase in a file is all that's required to encrypt. To decrypt, the openssl enc tool is used.
    *   no standalone server mode  
        For a simple server, launching via the ubiquitous inetd/xinetd is all that's needed. The super server provides most of the options present in pidentd.
    *   no protocol extensions  
        The <kbd>VERSION</kbd> and <kbd>QUIT</kbd> commands are unnecessary, a security risk in the case of <kbd>VERSION</kbd>, and a violation of RFC 1413 protocol. As they are not used by any client, they have been intentionally omitted. The "<kbd>-e</kbd>" option is instead used to mask error messages.  

    *   no automatic verbose encryption  
        Encrypting replies does not automatically include port and time information, which makes the reply excessively long. This information may be included with the "<kbd>--verbose</kbd>" option.
4.  HOW TO INCREASE PRIVACY
    *   You can allow users to either opt-out or opt-in from exposing their userid creating a file in their home directory (defaults are "<samp>~/.noident</samp>" and "<samp>~/.ident</samp>" respectively) and by setting the appropriate server option ("<kbd>-N</kbd>" or "<kbd>--ident</kbd>"). If both options are set then "<samp>~/.noident</samp>" will cancel out a "<samp>~/.ident</samp>" if both are present. If a file is present (or not present) which indicates that the user does not wish his information to be revealed, a <samp>HIDDER-USER</samp> error message is returned.
    *   If you just want an ident server to speed up broken servers that insist on some form of ident but you don't want to reveal any usernames, you can make authd "lie" to clients and tell them that the ports are owned by any arbitrary user with the "<kbd>--username</kbd>" option. When set to its default, the authd daemon will reply with either <samp>NO-USER</samp> errors or "<samp>nobody</samp>" as the port owner. Note that the argument supplied to "<kbd>--username</kbd>" must be a valid username. As some daemons do run as "<samp>nobody</samp>", you may wish to create a special username just for authd, such as "<samp>somebody</samp>", using the command:

        <samp>$ <kbd>/usr/sbin/useradd -s /sbin/nologin -r somebody</kbd></samp>

    *   Encryption allows the system administrator owning the authd server to be aware of any ident information that is sent to him from remote sites while not unnecessarily exposing the usernames to any anonymous system.
    *   The "<kbd>-e</kbd>" option can be used to return <samp>UNKNOWN-ERROR</samp> instead of <samp>INVALID-PORT</samp>, <samp>NO-USER</samp>, and <samp>HIDDEN-USER</samp>.  

5.  HOW TO USE ENCRYPTION
    1.  put a plain text password or pass phrase that is terminated by a newline in the file "<samp>/etc/ident.key</samp>". Any additional data after the newline is ignored. If the pass phrase is in a different file and/or location, use the "<kbd>--passwd</kbd>" option to tell authd where it is.
    2.  Make sure the owner/group and permissions are set so that the daemon (which usually runs as "<samp>nobody</samp>" if you use the default xinetd configuration file) can read it. Make sure that other can't read or write to it by using:

        <samp>$ <kbd>chmod o-rw /etc/ident.key</kbd></samp>

        authd will refuse to encrypt if this is not done.

    3.  To decrypt the string, the "<kbd>openssl</kbd>" tool (using the "<kbd>enc</kbd>" sub-tool) is needed. If the base64 encrypted string is longer than 64 characters, it will need to be broken into multiple lines of 64 characters or less (why? because openssl enc -base64 doesn't like it any other way-- even though base64 only needs line breaks for e-mail). Feed the short base64 string into the command:

        <samp>$ <kbd>/usr/bin/openssl enc -d -base64 -aes-128-cbc -pass file:/etc/ident.key</kbd></samp>

        (Change the cipher to what's appropriate if you did not use the default for the "<kbd>-E</kbd>" authd option or the default was changed in <samp>config.h</samp>) Use <kbd>enc</kbd>'s <kbd>-in</kbd> option if the base64 encryption is stored in a file rather than being piped into stdin)

    4.  **Do understand the security ramifications of storing a password/pass phrase in unencrypted form on a file system.** A system is secure if the cost of breaking the system is greater than the value of the data. Thus, do not increase the value of the authd password by using it anywhere else-- it should only be used to encrypt usernames & userids and address/port info returned by "<kbd>--verbose</kbd>" -- (relatively low value information already readable by any local user)
6.  INTERNATIONALIZATION
    *   Sometimes, the username and/or gecos field returned by the system may not be in ASCII. An example would be a system that authenticates against accounts stored on Windows. Windows permits non-ASCII in their usernames and Name/Comment descriptions. In these cases, use the "<kbd>--codeset</kbd>" option to specify the character encoding/charset used. This will _not_ convert any messages; it will simply inform the client as to the character encoding. The character encoding will _not_ be sent to the client if the response appears to be all ASCII (all printable characters; no control characters), even if the option is specified.
    *   in the rare case that the string to be sent is not ASCII, a <kbd>--codeset</kbd> has been specified without the optional parameter, and the program is unable to determine the codeset used by the operating system, "<samp>X-UNKNOWN</samp>" will be returned as the codeset.
    *   You may want error messages (also local timestamps with the --verbose option) to be sent in a different locale from the current locale (inetd/xinetd often is configured to launch daemons in the "<kbd>C</kbd>" locale). The locale to use can be configured with the "<kbd>--lang</kbd>" option. By default, the daemon starts in the locale of the parent (usually xinetd/inetd) that launched it. If <kbd>--codeset</kbd> is also specified, it overrides the character encoding of the specified locale.

        Be aware that many system log daemons are not capable of handling non-ASCII yet, so combining this with the "<kbd>-l</kbd>" option may not produce readable syslog messages.

7.  EXTENDED ERROR MESSAGES

    These only appear when authd is launched with the "<kbd>--xerror</kbd>" option, because some server administrators do not believe in giving outsiders any useful information regarding the state of their servers. However, the <kbd>--xerror</kbd> is useful for diagnostics and troubleshooting.

    *   <samp>X-PROC</samp>  
        either <samp>/proc/net/tcp</samp> or <samp>/proc/net/tcp6</samp> was not in the format that authd expected it to be in. This may be because:
        1.  the files are not part of a true linux <samp>/proc</samp> filesystem
        2.  you are running a modified or experimental kernel
        3.  you are running a kernel much newer than this program's last update and the file format has changed
        4.  the proc file macros in config.h have been changed to point to something else
    *   <samp>X-NAME</samp>  
        A username was specified as an argument, but the username couldn't be found in the password database (<samp>/etc/passwd</samp>, NIS, or whatever the system uses).
    *   <samp>X-UID</samp>  
        The UID taken from <samp>/proc/net/tcp6</samp> or <samp>/proc/net/tcp</samp> couldn't be found in the password database.
    *   <samp>X-FILE</samp>  
        The pathname for the <samp>.ident</samp> or <samp>.noident</samp> file (home directory path + filename) was excessively long or bogus.
    *   <samp>X-CRYPTO</samp>  
        Suffixed by zero or more sequences of dashes and eight digit hexadecimal numbers. Either the pass phrase file couldn't be opened (wrong filename, doesn't exist, wrong permissions (must be readable by authd and NOT readable/writable by "others"), the pass phrase was too short for the given encryption, the crypto algorithm was inappropriate for the type of data (for example, not symmetric or does not permit non-fixed lengths), or some other internal (usually memory resource related) condition.
    *   <samp>X-ERRNO</samp>  
        Suffixed with a dash and a decimal number corresponding to what was returned by errno. Usually will occur due to an I/O error or an out-of-memory condition. On Linux, <samp>2</samp> is a "file not found" and <samp>12</samp> is an out of memory condition. Note that some out of memory conditions will cause the server to exit before printing a message.  

    *   <samp>X-RFC1413</samp>  
        The userid reply was longer than 512 characters and/or contained CRLF. While this shouldn't happen with sane data, this could possibly occur if an exceptionally long/strange gecos field and the combination of "<kbd>--verbose</kbd>" and "<kbd>--fn</kbd>".
