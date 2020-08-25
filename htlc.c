#include <memory.h>
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "common.h"
#include "protocol.h"


/*
 * HTLC -> Toyimplementation of a HTLC withouth signature verification.
 *
 * CKB_args refers to the type_args field in the Script datastructure of CKB.
 *  table Script {
 *     code_hash:      Byte32,
 *     hash_type:      byte,
 *     args:           Bytes, // <- CKB_args
 *  }
 *
 * CKB_witnesses refers to the witnesses field of the current TX.
 *
 * As a hash we will use the Blake160-Hash of the secret message, which is a
 * random string message.
 * CKB_args: Hash(secret_msg) && PubKey Fingerprint A && PubKey Fingerprint B.
 * CKB_witnesses: Either secret_msg || block_header.
 */
#define BLAKE2B_BLOCK_SIZE 32
#define HEADER_SIZE 1552
#define SCRIPT_LEN 32768 // 32KB
#define SCRIPT_ARG_LEN 20
#define MAX_WITNESS_SIZE 32768
#define BLOCKTIME 20

int extract_witness_secret(uint8_t *witness, uint64_t len, mol_seg_t *secret_seg);
int extract_script_secret(mol_seg_t *real_hash);
int extract_header_number(int headeridx, uint64_t ckb_option, uint64_t *blocknr);
bool unlock_hashlock(mol_seg_t real_hash, uint64_t witness_len);
bool check_blocktime(unsigned char *witness, uint64_t witness_len);

int main(int argc, char* argv[]) {
  int ret;
  mol_seg_t real_hash;
  ret = extract_script_secret(&real_hash);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // TODO: load witness in a correct way. check implementation of
  // `extract_witness_lock()` from `common.h` in `ckb-system-scripts` for
  // reference.
  if (unlock_hashlock(real_hash, witness_len)) {
    return 0;
  }

  //if (check_blocktime(witness, witness_len)) {
  //  // signature verifcation is missing here. Anyone can claim funds after the
  //  // lock expired.
  //  return 0;
  //}

  return ERROR_HTLC_FAILURE;
}

// check_blocktime is given a witness with according length, extracts the
// original `blocknumber` where the HTLC was created and compares it to the
// `blocknumber` within the block that was referenced in the HtlcWitness struct.
bool check_blocktime(unsigned char *witness, uint64_t witness_len) {
  int ret;
  // block header index for current transaction
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = witness_len;
  mol_seg_t givenHeaderIdx;
  givenHeaderIdx = MolReader_HtlcWitness_get_blockheader(&witness_seg);
  uint32_t headeridx;
  memcpy(&headeridx, givenHeaderIdx.ptr, sizeof(headeridx));

  uint64_t inputHeaderNumber;
  uint64_t givenHeaderNumber;
  ret = extract_header_number(0, CKB_SOURCE_GROUP_INPUT, &inputHeaderNumber);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = extract_header_number(headeridx, CKB_SOURCE_HEADER_DEP, &givenHeaderNumber);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (givenHeaderNumber < inputHeaderNumber + BLOCKTIME) {
    return false;
  }

  return true;
}

// extract_header_number extracts the blocknumber from a blockheader. Given
// parameters decide which blockheader is being picked from the surrounding
// transaction.
int extract_header_number(int headeridx, uint64_t ckb_option, uint64_t *blocknr) {
  int ret;
  unsigned char header[HEADER_SIZE];
  // block header for current input cells with same script.
  uint64_t len = HEADER_SIZE;
  ret = ckb_load_header(header, &len, 0, headeridx, ckb_option);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t header_seg;
  header_seg.ptr = (uint8_t *) header;
  header_seg.size = len;

  if (MolReader_Header_verify(&header_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t header_raw;
  header_raw = MolReader_Header_get_raw(&header_seg);

  if (MolReader_RawHeader_verify(&header_raw, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t blocknr_seg;
  blocknr_seg = MolReader_RawHeader_get_number(&header_raw);
  memcpy(&blocknr, blocknr_seg.ptr, sizeof(blocknr));
  return CKB_SUCCESS;
}

// extract_script_secret extracts the `secret` (also known as `preimage`) from
// `Script.args`.
int extract_script_secret(mol_seg_t *real_hash) {
  int ret;
  size_t offset = 0;
  unsigned char script[SCRIPT_LEN];
  uint64_t len = SCRIPT_LEN;

  // Load encoded script struct into memory.
  ret = ckb_load_script(script, &len, offset);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *) script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  // now we are ready to retrieve the script argument, the blake160 hash of secret.
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  *real_hash = MolReader_HtlcArgs_get_hashedSecret(&args_seg);
  if (MolReader_BytesOpt_is_none(real_hash)) {
    return ERROR_ENCODING;
  }

  if (real_hash->size != SCRIPT_ARG_LEN) {
    return ERROR_ARGUMENTS_LEN;
  }

  return CKB_SUCCESS;
}

// unlock_hashlock tries to unlock the hashlock. It extracts the witness secret
// applies Blake2b and compares the original BLAKE160-hash (from `Script.args`)
// to the calculated BLAKE160-hash (from `blake2b(HtlcWitness.secret)`.
bool unlock_hashlock(mol_seg_t real_hash, uint64_t witness_len) {
  int ret;
  mol_seg_t witness_sec_seg;
  ret = extract_witness_secret(witness, witness_len, &witness_sec_seg);
  if (ret != CKB_SUCCESS) {
    return false;
  }
  if (witness_len == 0) {
    return false;
  }

  unsigned char claimed_hashed[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, (char*)witness_sec_seg.ptr, witness_sec_seg.size);
  blake2b_final(&blake2b_ctx, claimed_hashed, BLAKE2B_BLOCK_SIZE);

  if (memcmp(real_hash.ptr, claimed_hashed, SCRIPT_ARG_LEN) != 0) {
    return false;
  }

  return true;
}

// extract_witness_secret extracts the secret from `HtlcWitness` and writes it
// to given `secret_seg`.
int extract_witness_secret(uint8_t *witness, uint64_t len, mol_seg_t *secret_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_HtlcWitness_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t sec_seg = MolReader_HtlcWitness_get_secret(&witness_seg);
  if (MolReader_BytesOpt_is_none(&sec_seg)) {
    return ERROR_ENCODING;
  }

  *secret_seg = MolReader_Bytes_raw_bytes(&sec_seg);
  return CKB_SUCCESS;
}
