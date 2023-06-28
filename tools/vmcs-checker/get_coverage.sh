#!/bin/bash

while true
do
  sudo ./vmcscov # Assuming this runs your tests

  lcov --directory . --capture --output-file coverage_run.info 

  # Check if coverage.info exists and if not, rename coverage_run.info to become the initial coverage.info
  if [ ! -f coverage.info ]; then
    mv coverage_run.info coverage.info
  else
    # Merge the coverage reports
    lcov --add-tracefile coverage.info --add-tracefile coverage_run.info --output-file coverage.info
  fi

  # Generate HTML report with function coverage
  genhtml coverage.info --branch-coverage --output-directory out

  # Wait for a specified interval (e.g., 5 seconds) before the next iteration
#   sleep 1
done