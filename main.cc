#include <stdint.h>
#include <stdio.h>
#include <cstddef>
#include <memory>

#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>

#include "scoped_ptr.h"
#include "test_data.h"

enum SignatureType { ES256 = 0, ES384 = 1, ES521 = 2, PS256 = 3 };

extern "C" {
typedef bool (*callback)(const uint8_t *payload, size_t payload_len,
                         const uint8_t *cert_chain, size_t cert_chain_len,
                         const uint8_t *ee_cert, size_t ee_cert_len,
                         const uint8_t *signature, size_t signature_len,
                         uint8_t algorithm);
bool verify_signature_with_cpp(const uint8_t *payload, size_t payload_len,
                               const uint8_t *signature, size_t signature_len,
                               callback);
}

/* Verification function called from cose-rust.
 * Returns true if everything goes well and the signature is good, false in any
 * other case. */
bool verify_callback(const uint8_t *payload, size_t payload_len,
                     const uint8_t *cert_chain, size_t cert_chain_len,
                     const uint8_t *ee_cert, size_t ee_cert_len,
                     const uint8_t *signature, size_t signature_len,
                     uint8_t signature_algorithm) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  if (!slot) {
    return false;
  }

  CK_MECHANISM_TYPE mechanism;
  SECOidTag oid;
  uint32_t hash_length;
  switch (signature_algorithm) {
    case (ES256):
      mechanism = CKM_ECDSA;
      oid = SEC_OID_SHA256;
      hash_length = 32;
      break;
    default:
      return false;
  }

  uint8_t hash_buf[hash_length];
  SECStatus rv = PK11_HashBuf(oid, hash_buf, payload, payload_len);
  if (rv != SECSuccess) {
    return false;
  }
  SECItem hash_item = {siBuffer, hash_buf, hash_length};
  CERTCertDBHandle *db_handle = CERT_GetDefaultCertDB();
  if (!db_handle) {
    return false;
  }
  SECItem der_cert = {siBuffer, const_cast<uint8_t *>(ee_cert),
                      static_cast<unsigned int>(ee_cert_len)};
  ScopedCERTCertificate cert(
      CERT_NewTempCertificate(db_handle, &der_cert, nullptr, false, true));
  if (!cert) {
    return false;
  }
  ScopedSECKEYPublicKey key(CERT_ExtractPublicKey(cert.get()));
  if (!key) {
    return false;
  }
  SECItem signature_item = {siBuffer, const_cast<uint8_t *>(signature),
                            static_cast<unsigned int>(signature_len)};
  rv = PK11_VerifyWithMechanism(key.get(), mechanism, nullptr, &signature_item,
                                &hash_item, nullptr);
  if (rv != SECSuccess) {
    return false;
  }

  (void)cert_chain;
  (void)cert_chain_len;
  printf("Verification successful\n");

  return true;
}

int main() {
  SECStatus rv = NSS_NoDB_Init(nullptr);
  if (rv != SECSuccess) {
    return 1;
  }
  bool result =
      verify_signature_with_cpp(PAYLOAD, 20, SIGNATURE, 1062, verify_callback);
  return result ? 0 : 1;
}
