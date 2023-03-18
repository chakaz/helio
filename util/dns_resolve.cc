// Copyright 2022, Roman Gershman.  All rights reserved.
// See LICENSE for licensing terms.
//

#include "util/dns_resolve.h"

#include <ares.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <boost/fiber/future.hpp>

#include "base/logging.h"
#include "util/fibers/fibers_ext.h"

namespace util {
namespace {

using namespace std;

struct DnsResolveCallbackArgs {
  boost::fibers::promise<std::error_code> promise;
  char* dest_ip;
};

void DnsResolveCallback(void* ares_arg, int status, int timeouts, hostent* hostent) {
  CHECK(ares_arg != nullptr);
  auto* cb_args = static_cast<DnsResolveCallbackArgs*>(ares_arg);
  if (status != ARES_SUCCESS || hostent == nullptr) {
    cb_args->promise.set_value(make_error_code(errc::address_not_available));
    return;
  }

  if (hostent->h_addrtype != AF_INET) {
    // We currently only support IPv4
    cb_args->promise.set_value(make_error_code(errc::address_not_available));
  }

  char** addr = hostent->h_addr_list;
  while (addr != nullptr) {
    ares_inet_ntop(AF_INET, *addr, cb_args->dest_ip, INET_ADDRSTRLEN);
    cb_args->promise.set_value(error_code());
    return;
  }

  cb_args->promise.set_value(make_error_code(errc::address_not_available));
}

}  // namespace

error_code DnsResolve(const char* dns, uint32_t wait_ms, char dest_ip[]) {
  // TODO: Should we cache this value?
  ares_channel channel;
  CHECK_EQ(ares_init(&channel), ARES_SUCCESS);

  DnsResolveCallbackArgs cb_args;
  cb_args.dest_ip = dest_ip;
  ares_gethostbyname(channel, dns, AF_INET, DnsResolveCallback, &cb_args);

  ares_destroy(channel);

  return cb_args.promise.get_future().get();
}

}  // namespace util
