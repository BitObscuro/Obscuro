#include <arpa/inet.h>

#include "MyEnclave_u.h"


in_addr_t ocall_inet_addr (const char *cp)
{
	return inet_addr(cp);
}

in_addr_t ocall_inet_lnaof (struct in_addr in)
{
	return inet_lnaof(in);
}

struct in_addr ocall_inet_makeaddr (in_addr_t net, in_addr_t host)
{
	return inet_makeaddr(net, host);
}

in_addr_t ocall_inet_netof (struct in_addr in)
{
	return inet_netof(in);
}

in_addr_t ocall_inet_network (const char *cp)
{
	return inet_network(cp);
}

char *ocall_inet_ntoa (struct in_addr in)
{
	return inet_ntoa(in);
}

int ocall_inet_pton (int af, const char *cp, void *buf)
{
	return inet_pton(af, cp, buf);
}

char *ocall_inet_ntop (int af,  const void *cp, char *buf, socklen_t len)
{
	return (char*)inet_ntop(af, cp, buf, len);
}