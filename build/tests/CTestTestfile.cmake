# CMake generated Testfile for 
# Source directory: I:/ChanceCode/tests
# Build directory: I:/ChanceCode/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[chancecodec_simple_add]=] "I:/ChanceCode/build/chancecodec.exe" "I:/ChanceCode/tests/simple_add.ccb" "--backend" "x86" "--output" "I:/ChanceCode/build/tests/simple_add.asm")
set_tests_properties([=[chancecodec_simple_add]=] PROPERTIES  _BACKTRACE_TRIPLES "I:/ChanceCode/tests/CMakeLists.txt;5;add_test;I:/ChanceCode/tests/CMakeLists.txt;0;")
add_test([=[chancecodec_verify_simple_add]=] "E:/Program Files/CMake/bin/cmake.exe" "-E" "compare_files" "I:/ChanceCode/tests/expected/simple_add.asm" "I:/ChanceCode/build/tests/simple_add.asm")
set_tests_properties([=[chancecodec_verify_simple_add]=] PROPERTIES  DEPENDS "chancecodec_simple_add" _BACKTRACE_TRIPLES "I:/ChanceCode/tests/CMakeLists.txt;13;add_test;I:/ChanceCode/tests/CMakeLists.txt;0;")
add_test([=[chancecodec_complex_ops]=] "I:/ChanceCode/build/chancecodec.exe" "I:/ChanceCode/tests/complex_ops.ccb" "--backend" "x86" "--output" "I:/ChanceCode/build/tests/complex_ops.asm")
set_tests_properties([=[chancecodec_complex_ops]=] PROPERTIES  _BACKTRACE_TRIPLES "I:/ChanceCode/tests/CMakeLists.txt;24;add_test;I:/ChanceCode/tests/CMakeLists.txt;0;")
add_test([=[chancecodec_verify_complex_ops]=] "E:/Program Files/CMake/bin/cmake.exe" "-E" "compare_files" "I:/ChanceCode/tests/expected/complex_ops.asm" "I:/ChanceCode/build/tests/complex_ops.asm")
set_tests_properties([=[chancecodec_verify_complex_ops]=] PROPERTIES  DEPENDS "chancecodec_complex_ops" _BACKTRACE_TRIPLES "I:/ChanceCode/tests/CMakeLists.txt;32;add_test;I:/ChanceCode/tests/CMakeLists.txt;0;")
