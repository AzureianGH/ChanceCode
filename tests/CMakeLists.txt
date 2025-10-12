set(TEST_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/simple_add.ccb)
set(TEST_EXPECTED ${CMAKE_CURRENT_SOURCE_DIR}/expected/simple_add.asm)
set(TEST_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/simple_add.asm)

add_test(
    NAME chancecodec_simple_add
    COMMAND $<TARGET_FILE:chancecodec>
        ${TEST_INPUT}
        --backend x86
        --output ${TEST_OUTPUT}
)

add_test(
    NAME chancecodec_verify_simple_add
    COMMAND ${CMAKE_COMMAND} -E compare_files ${TEST_EXPECTED} ${TEST_OUTPUT}
)

set_tests_properties(chancecodec_verify_simple_add PROPERTIES DEPENDS chancecodec_simple_add)

set(COMPLEX_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/complex_ops.ccb)
set(COMPLEX_EXPECTED ${CMAKE_CURRENT_SOURCE_DIR}/expected/complex_ops.asm)
set(COMPLEX_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/complex_ops.asm)

add_test(
    NAME chancecodec_complex_ops
    COMMAND $<TARGET_FILE:chancecodec>
        ${COMPLEX_INPUT}
        --backend x86
        --output ${COMPLEX_OUTPUT}
)

add_test(
    NAME chancecodec_verify_complex_ops
    COMMAND ${CMAKE_COMMAND} -E compare_files ${COMPLEX_EXPECTED} ${COMPLEX_OUTPUT}
)

set_tests_properties(chancecodec_verify_complex_ops PROPERTIES DEPENDS chancecodec_complex_ops)
