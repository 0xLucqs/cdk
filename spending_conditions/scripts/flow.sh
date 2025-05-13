#!/bin/bash

scarb --profile release build

readonly LAYOUT=starknet
readonly PROGRAM_NAME=spending_conditions

readonly TRACE_OUTPUT_DIR=outputs/$PROGRAM_NAME/trace
readonly PIE_OUTPUT_DIR=outputs/$PROGRAM_NAME/pie

readonly NONCE_LOW=$1
readonly NONCE_HIGH=$2
readonly SIG_R=$3
readonly SIG_S=$4

readonly PROGRAM_ARGS="[$NONCE_LOW $NONCE_HIGH $SIG_R $SIG_S]"

mkdir -p $TRACE_OUTPUT_DIR

echo "generate trace"
cairo1-run target/release/$PROGRAM_NAME.sierra.json \
  --args "$PROGRAM_ARGS" \
  --layout=$LAYOUT \
  --air_public_input=$TRACE_OUTPUT_DIR/public-input.json \
  --air_private_input=$TRACE_OUTPUT_DIR/private-input.json \
  --trace_file=$TRACE_OUTPUT_DIR/trace.bin \
  --memory_file=$TRACE_OUTPUT_DIR/memory.bin \
  --proof_mode 

readonly PROOF_OUTPUT_DIR=outputs/$PROGRAM_NAME/proof

mkdir -p $PROOF_OUTPUT_DIR

echo "generate proof"
# This will fail at first run. You have to go edit the path in the private-input.json file
# see: https://github.com/starkware-libs/stwo-cairo/issues/337
# just keep:
# "trace_path": "trace.bin",
# "memory_path": "memory.bin"
adapted_stwo --pub_json $TRACE_OUTPUT_DIR/public-input.json --priv_json $TRACE_OUTPUT_DIR/private-input.json --proof_path stwo-proof.json --verify
