#ifndef EXTENSION_NAMES_H_
#define EXTENSION_NAMES_H_
#include <linux/inet_diag.h>

static const char *extensions_map[]={
	[INET_DIAG_NONE] = "NONE",
	[INET_DIAG_MEMINFO] = "MEMINFO",
	[INET_DIAG_INFO] = "INFO",
	[INET_DIAG_VEGASINFO] = "VEGASINFO",
	[INET_DIAG_CONG] = "CONG",
	[INET_DIAG_TOS] = "TOS",
	[INET_DIAG_TCLASS] = "TCLASS",
	[INET_DIAG_SKMEMINFO] = "SKMEMINFO",
	[INET_DIAG_SHUTDOWN] = "SHUTDOWN",
	[INET_DIAG_DCTCPINFO] = "DCTCPINFO",
	[INET_DIAG_PROTOCOL] = "PROTOCOL",
	[INET_DIAG_SKV6ONLY] = "SKV6ONLY",
	[INET_DIAG_LOCALS] = "LOCALS",
	[INET_DIAG_PEERS] = "PEERS",
	[INET_DIAG_PAD] = "PAD",
	[INET_DIAG_MARK] = "MARK",
	[INET_DIAG_BBRINFO] = "BBRINFO",
	[INET_DIAG_CLASS_ID] = "CLASS_ID",
	[INET_DIAG_MD5SIG] = "MD5SIG",
	[INET_DIAG_ULP_INFO] = "ULP_INFO",
	[INET_DIAG_SK_BPF_STORAGES] = "SK_BPF_STORAGES",
	[INET_DIAG_CGROUP_ID] = "CGROUP_ID",
	[INET_DIAG_SOCKOPT] = "SOCKOPT",
};


#endif