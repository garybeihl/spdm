# Test dependencies (daemon deps come via spdmd_deps)
test_deps = [
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    dependency('gmock', required: true),
    libspdm_dep,
]

<<<<<<< HEAD
tests = [
    'test_mctp_transport_discovery',
    'test_spdm_discovery',
    'test_policy_manager',
]

=======
# Common source files needed by multiple tests
common_src = [
    'test_mctp_transport_discovery.cpp',
    'test_mctp_helper.cpp',
    'test_component_integrity.cpp',
    'mock_libspdm.cpp',
    '../requester/mctp_transport_discovery.cpp',
    '../requester/spdm_discovery.cpp',
    '../requester/utils/mapper.cpp',
    '../requester/libspdm_mctp_transport.cpp',
    '../requester/spdm_device_secret_lib_stub.cpp',
    '../requester/component_integrity_dbus.cpp',
]

# Define test executables
tests = ['mctp_transport_discovery', 'mctp_helper', 'component_integrity']

# Build and register each test
>>>>>>> 7f03cd4 (spdmd: Implement Digest)
foreach t : tests
    test(
        t,
        executable(
            t,
            t + '.cpp',
            link_with: spdmd_lib,
            dependencies: spdmd_deps + test_deps,
            include_directories: spdmd_includes,
        ),
    )
endforeach
