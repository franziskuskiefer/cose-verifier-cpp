/* Scoped pointers for NSS raw pointers. */

#ifndef scoped_ptr_h__
#define scoped_ptr_h__

#include <pkcs11t.h>
#include <secmodt.h>
#include <cert.h>

struct ScopedDelete {
  void operator()(CERTCertificate *cert) { CERT_DestroyCertificate(cert); }
  void operator()(SECKEYPublicKey *key) { SECKEY_DestroyPublicKey(key); }
  void operator()(PK11SlotInfo *slot) { PK11_FreeSlot(slot); }
};

template <class T>
struct ScopedMaybeDelete {
  void operator()(T *ptr) {
    if (ptr) {
      ScopedDelete del;
      del(ptr);
    }
  }
};

#define SCOPED(x) typedef std::unique_ptr<x, ScopedMaybeDelete<x> > Scoped##x

SCOPED(CERTCertificate);
SCOPED(SECKEYPublicKey);
SCOPED(PK11SlotInfo);

#undef SCOPED

#endif // scoped_ptr_h__
