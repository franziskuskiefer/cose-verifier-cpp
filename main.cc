#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <cstddef>
#include <memory>

#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>

#include "scoped_ptr.h"
#include "test_data.h"

enum SignatureType { ES256 = 0, ES384 = 1, ES512 = 2, PS256 = 3 };

extern "C" {
typedef bool (*callback)(const uint8_t *payload, size_t payload_len,
                         const uint8_t **cert_chain, size_t cert_chain_len,
                         const size_t *certs_len, const uint8_t *ee_cert,
                         size_t ee_cert_len, const uint8_t *signature,
                         size_t signature_len, uint8_t algorithm);
bool verify_signature_ffi(const uint8_t *payload, size_t payload_len,
                          const uint8_t *signature, size_t signature_len,
                          callback);
}

void check_hard_coded_certs(const uint8_t **cert_chain, size_t cert_chain_len,
                            const size_t *certs_len) {
  // Very hacky and fragile check that the intermediate certs are correct.
  switch (cert_chain_len) {
    case 2: {
      const uint8_t *cert = cert_chain[0];
      size_t cert_len = certs_len[0];
      assert(cert_len == sizeof(P256_ROOT));
      assert(memcmp(cert, P256_ROOT, cert_len) == 0);
      cert = cert_chain[1];
      cert_len = certs_len[1];
      assert(cert_len == sizeof(P256_INT));
      assert(memcmp(cert, P256_INT, cert_len) == 0);
      break;
    }
    case 4: {
      const uint8_t *cert = cert_chain[0];
      size_t cert_len = certs_len[0];
      assert(cert_len == sizeof(P256_ROOT));
      assert(memcmp(cert, P256_ROOT, cert_len) == 0);
      cert = cert_chain[1];
      cert_len = certs_len[1];
      assert(cert_len == sizeof(P256_INT));
      assert(memcmp(cert, P256_INT, cert_len) == 0);
      cert = cert_chain[2];
      cert_len = certs_len[2];
      assert(cert_len == sizeof(RSA_ROOT));
      assert(memcmp(cert, RSA_ROOT, cert_len) == 0);
      cert = cert_chain[3];
      cert_len = certs_len[3];
      assert(cert_len == sizeof(RSA_INT));
      assert(memcmp(cert, RSA_INT, cert_len) == 0);
      break;
    }
    default:
      // In this case something went wrong.
      assert(true == false);
  }
}

/* Verification function called from cose-rust.
 * Returns true if everything goes well and the signature is good, false in any
 * other case. */
bool verify_callback(const uint8_t *payload, size_t payload_len,
                     const uint8_t **cert_chain, size_t cert_chain_len,
                     const size_t *certs_len, const uint8_t *ee_cert,
                     size_t ee_cert_len, const uint8_t *signature,
                     size_t signature_len, uint8_t signature_algorithm) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  if (!slot) {
    return false;
  }

  CK_MECHANISM_TYPE mechanism;
  SECOidTag oid;
  uint32_t hash_length;
  SECItem param = {siBuffer, nullptr, 0};
  CK_RSA_PKCS_PSS_PARAMS rsa_pss_params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
  switch (signature_algorithm) {
    case (ES256):
      mechanism = CKM_ECDSA;
      oid = SEC_OID_SHA256;
      hash_length = 32;
      break;
    case (PS256):
      mechanism = CKM_RSA_PKCS_PSS;
      oid = SEC_OID_SHA256;
      hash_length = 32;
      param = {siBuffer, reinterpret_cast<unsigned char *>(&rsa_pss_params),
               sizeof(rsa_pss_params)};
      break;
    default:
      return false;
  }
  printf("Verifying signature (%d, %lu)\n", oid, mechanism);
  check_hard_coded_certs(cert_chain, cert_chain_len, certs_len);

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
  rv = PK11_VerifyWithMechanism(key.get(), mechanism, &param, &signature_item,
                                &hash_item, nullptr);
  if (rv != SECSuccess) {
    return false;
  }

  return true;
}

int main() {
  SECStatus rv = NSS_NoDB_Init(nullptr);
  if (rv != SECSuccess) {
    return 1;
  }
  printf("Verifying single ES256 (191, 4161) COSE signature\n");
  bool result =
      verify_signature_ffi(PAYLOAD, 20, SIGNATURE, 1062, verify_callback);

  printf(
      "Verifying COSE signature with ES256 (191, 4161) and PS256 (191, 13)\n ");
  result &= verify_signature_ffi(PAYLOAD, 20, SIGNATURE_ES256_PS256, 3480,
                                 verify_callback);
  printf("%s\n",
         result ? "Verification successful :)" : "Verification failed :(");
  return result ? 0 : 1;
}
