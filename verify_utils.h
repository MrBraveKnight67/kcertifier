bool verify_hashes(
    Report& report, const byte* expected_enclave_hash,
    const byte* expected_sm_hash, const byte* dev_public_key);

// Verifies that the nonce returned in the attestation report is
// the same as the one sent.
bool verify_data(Report& report, const int nonce_size, byte* nonce);

// Computes the hash of the expected EApp running in the enclave.
void compute_expected_enclave_hash(byte* expected_enclave_hash);

// Computes the hash of the expected Security Monitor (SM).
void compute_expected_sm_hash(byte* expected_sm_hash);