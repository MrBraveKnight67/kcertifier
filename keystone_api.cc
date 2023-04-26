#include "verify_utils.h"

typedef unsigned char byte;

#define KEYSTONE_CERTIFIER
#ifdef KEYSTONE_CERTIFIER
bool keystone_Init(const int cert_size, byte *cert);
bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out);
bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);
bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out);
bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out);
#endif


typedef struct KeystoneFunctions {
  bool (*Attest)(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out);
  bool (*Verify)(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);
  bool (*Seal)(int in_size, byte* in, int* size_out, byte* out);
  bool (*Unseal)(int in_size, byte* in, int* size_out, byte* out);
} KeystoneFunctions;


bool keystone_Init(const int cert_size, byte *cert) {
  // qq: should this do anything??
}

bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out) {
    assert(what_to_say_size <= 1024);
    assert(attestation_size_out >= 1352);
    return attest_enclave((void *) attestation_out, what_to_say, what_to_say_size);
}

// qq: what is measurement_out?
bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out) {
  assert(attestation_size == sizeof(struct report_t));

  /* Compute expected hashes */
  
  // qq: keystone expects this to be running host-side, trusted host, that can launch an enclave that will measure itself.
  // option1: replicate the code into the verifier (since it's running inside an enclave)?
  // option2: compute these beforehand and store with verifier
  byte expected_enclave_hash[MDSIZE];
  compute_expected_enclave_hash(expected_enclave_hash);

  byte expected_sm_hash[MDSIZE];
  compute_expected_sm_hash(expected_sm_hash);

  /* Actual report checks */

  Report report;
  report.fromBytes(attestation);

  if(verify_hashes(report, expected_enclave_hash, expected_sm_hash, _sanctum_dev_public_key)) {
    return 1;
  }

  return verify_data(report, what_to_say_size, what_to_say);
}

// to share between seal and unseal
bool keystone_getSealingKey(struct sealing_key& key_buffer) {
  char *key_identifier = "sealing-key";
  return get_sealing_key(&key_buffer, sizeof(key_buffer),
                        (void *)key_identifier, strlen(key_identifier));
}

bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out) {
  struct sealing_key key_buffer; // {key, signature}
  if (keystone_getSealingKey(key_buffer)) {
    return ret;
  }

  // todo algorithm of choice for encryption using the key
  return 0;
}

bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  struct sealing_key key_buffer;
  if (keystone_getSealingKey(key_buffer)) {
    return ret;
  }

  // todo algorithm of choice for decryption using the key
  return 0;
}
