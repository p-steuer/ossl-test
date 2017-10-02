### config.pm

Provides lists of different configurations and environments used by the other
test scripts.

### perf.pl

Usage: ./perf.pl [openssl tool path]

Runs the openssl speed tool in different environments.

### test.pl

Usage: ./test.pl [openssl source path]

Builds openssl with different configurations and runs the openssl test-suite in
different environments. Running the script as root user will cause some of the
tests to fail. Writes a .log-file.
