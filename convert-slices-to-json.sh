#!/usr/bin/env bash

cd slice-to-ast
npm install
cd -

cd proj-slices
for slice in *.txt; do
    slice="${PWD}/${slice}"
    slice_out="${slice%.txt}.json"
    (cd ../slice-to-ast/; npm run parser -- "${slice}" >"${slice_out}")
done

