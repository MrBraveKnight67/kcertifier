#include "verify_utils.h"

bool verify_hashes(
    Report& report, const byte* expected_enclave_hash,
    const byte* expected_sm_hash, const byte* dev_public_key) {
  if (report.verify(expected_enclave_hash, expected_sm_hash, dev_public_key)) {
    printf("Enclave and SM hashes match with expected.\n");
    return 0;
  } else {
    printf(
        "Either the enclave hash or the SM hash (or both) does not "
        "match with expeced.\n");
    report.printPretty();
    return 1;
  }
}

bool verify_data(Report& report, const int nonce_size, byte* nonce) {
  if (report.getDataSize() != nonce_size + 1) {
    const char error[] =
        "The size of the data in the report is not equal to the size of the "
        "nonce initially sent.";
    printf(error);
    report.printPretty();
    throw std::runtime_error(error);
  }
  byte* rep_nonce = (byte*) report.getDataSection();
  for (int i = 0; i < nonce_size; i++) {
    if (rep_nonce[i] != nonce[i]) {
      printf("Returned data in the report do NOT match with the nonce sent.\n");
      return 0;
    }
  }
  printf("Returned data in the report match with the nonce sent.\n");
  return 1;
}

// void compute_expected_enclave_hash(byte* expected_enclave_hash) {
//   Keystone::Enclave enclave;
//   Keystone::Params simulated_params = params_;
//   simulated_params.setSimulated(true);
//   // This will cause validate_and_hash_enclave to be called when
//   // isSimulated() == true.
//   enclave.init(eapp_file_.c_str(), rt_file_.c_str(), simulated_params);
//   memcpy(expected_enclave_hash, enclave.getHash(), MDSIZE);
// }

// void compute_expected_sm_hash(byte* expected_sm_hash) {
//   // It is important to make sure the size of the SM buffer we are
//   // measuring is the same as the size of the SM buffer allocated by
//   // the bootloader. See keystone/bootrom/bootloader.c for how it is
//   // computed in the bootloader.
//   const size_t sanctum_sm_size = 0x1ff000;
//   std::vector<byte> sm_content(sanctum_sm_size, 0);

//   {
//     // Reading SM content from file.
//     FILE* sm_bin = fopen(sm_bin_file_.c_str(), "rb");
//     if (!sm_bin)
//       throw std::runtime_error(
//           "Error opening sm_bin_file_: " + sm_bin_file_ + ", " +
//           std::strerror(errno));
//     if (fread(sm_content.data(), 1, sm_content.size(), sm_bin) <= 0)
//       throw std::runtime_error(
//           "Error reading sm_bin_file_: " + sm_bin_file_ + ", " +
//           std::strerror(errno));
//     fclose(sm_bin);
//   }

//   {
//     // The actual SM hash computation.
//     hash_ctx_t hash_ctx;
//     hash_init(&hash_ctx);
//     hash_extend(&hash_ctx, sm_content.data(), sm_content.size());
//     hash_finalize(expected_sm_hash, &hash_ctx);
//   }
// }
