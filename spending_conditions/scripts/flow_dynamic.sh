#!/bin/bash

scarb --profile release build

readonly LAYOUT=dynamic
readonly PROGRAM_NAME=spending_conditions
readonly CFG_AND_PARAMS_DIR=config_and_params

readonly TRACE_OUTPUT_DIR=outputs/$PROGRAM_NAME/trace

cairo1-run target/release/$PROGRAM_NAME.sierra.json \
  --layout=$LAYOUT \
  --args "[650157136941007917207724121471813482783483983289688285320161307177215463403 1655569645808460179723299787189716707852181277595105475126938070374837146371]"  \
  --cairo_layout_params_file=$CFG_AND_PARAMS_DIR/cairo_layout_params_file.json \
  --cairo_pie_output=$TRACE_OUTPUT_DIR/cairo-pie.zip


mkdir -p $TRACE_OUTPUT_DIR

cairo1-run target/release/$PROGRAM_NAME.sierra.json \
  --args "[650157136941007917207724121471813482783483983289688285320161307177215463403 1655569645808460179723299787189716707852181277595105475126938070374837146371]" \
  --layout=$LAYOUT \
  --air_public_input=$TRACE_OUTPUT_DIR/public-input.json \
  --air_private_input=$TRACE_OUTPUT_DIR/private-input.json \
  --trace_file=$TRACE_OUTPUT_DIR/trace.bin \
  --memory_file=$TRACE_OUTPUT_DIR/memory.bin \
  --cairo_layout_params_file=$CFG_AND_PARAMS_DIR/cairo_layout_params_file.json \
  --proof_mode 

# readonly PROOF_OUTPUT_DIR=outputs/$PROGRAM_NAME/proof

# mkdir -p $PROOF_OUTPUT_DIR

cpu_air_prover \
  --out_file=$PROOF_OUTPUT_DIR/proof.json \
  --private_input_file=$TRACE_OUTPUT_DIR/private-input.json \
  --public_input_file=$TRACE_OUTPUT_DIR/public-input.json \
  --prover_config_file=$CFG_AND_PARAMS_DIR/cpu_air_prover_config.json \
  --parameter_file=$CFG_AND_PARAMS_DIR/cpu_air_params.json

# stone-cli prove \
#   --prover_config_file $CFG_AND_PARAMS_DIR/cpu_air_prover_config.json  \
#   --cairo_program target/release/$PROGRAM_NAME.sierra.json \
#   --program_input "[650157136941007917207724121471813482783483983289688285320161307177215463403 1655569645808460179723299787189716707852181277595105475126938070374837146371]" \
#   --layout all-cairo \
#   --output $PROOF_OUTPUT_DIR/proof.json 


