project(
    'spdm',
    'cpp',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++23',
        'warning_level=3',
        'werror=true',
    ],
    version: '1.0',
    meson_version: '>=1.1.1',
)

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus')
systemd_dep = dependency('systemd')

# Try to find libspdm using pkg-config first
libspdm_dep = dependency('libspdm', required: false)

# If pkg-config doesn't work, find individual libspdm static libraries.
# Yocto installs them as libspdm_*_lib.a (e.g. libspdm_common_lib.a).
if not libspdm_dep.found()
    cpp = meson.get_compiler('cpp')
    libspdm_common = cpp.find_library('spdm_common_lib', required: false)
    libspdm_requester = cpp.find_library('spdm_requester_lib', required: false)
    libspdm_transport_mctp = cpp.find_library(
        'spdm_transport_mctp_lib',
        required: false,
    )
    libspdm_crypt = cpp.find_library('spdm_crypt_lib', required: false)
    libspdm_crypt_ext = cpp.find_library('spdm_crypt_ext_lib', required: false)
    libspdm_secured_message = cpp.find_library(
        'spdm_secured_message_lib',
        required: false,
    )
    libcryptlib_openssl = cpp.find_library('cryptlib_openssl', required: false)
    libmemlib = cpp.find_library('memlib', required: false)
    libmalloclib = cpp.find_library('malloclib', required: false)
    librnglib = cpp.find_library('rnglib', required: false)
    libplatform = cpp.find_library('platform_lib', required: false)
    libdebuglib = cpp.find_library('debuglib', required: false)

    libspdm_includedir = get_option('libspdm-includedir')
    if libspdm_includedir == ''
        libspdm_includedir = '/usr/include/libspdm'
    endif

    openssl_dep = dependency('openssl')

    if libspdm_common.found() and libspdm_requester.found()
        libspdm_dep = declare_dependency(
            dependencies: [
                libspdm_common,
                libspdm_requester,
                libspdm_transport_mctp,
                libspdm_crypt,
                libspdm_crypt_ext,
                libspdm_secured_message,
                libcryptlib_openssl,
                libmemlib,
                libmalloclib,
                librnglib,
                libplatform,
                libdebuglib,
                openssl_dep,
            ],
            compile_args: ['-isystem', libspdm_includedir],
        )
    else
        error('libspdm not found. Please ensure libspdm is installed.')
    endif
endif

spdmd_deps = [
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    libspdm_dep,
]
spdmd_includes = include_directories('requester')

spdmd_src = [
    'requester/spdm_discovery.cpp',
    'requester/spdm_responder_manager.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/policy_manager.cpp',
    'requester/utils/mapper.cpp',
    'requester/spdm_dbus_responder.cpp',
    'requester/component_integrity_dbus.cpp',
    'requester/trusted_component_dbus.cpp',
    'requester/spdm_device_secret_lib_stub.cpp',
    'requester/libspdm_mctp_transport.cpp',
    'requester/certificate_dbus.cpp',
]

spdmd_lib = static_library(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
)

install_data(
    'service/spdmd.service',
    install_dir: systemd_dep.get_variable('systemd_system_unit_dir'),
)

policy_cache_path = get_option('localstatedir') + '/lib/spdm/policy.json'

conf_data = configuration_data()
conf_data.set_quoted('POLICY_CACHE_PATH', policy_cache_path)

configure_file(output: 'config.hpp', configuration: conf_data)

executable(
    'spdmd',
    'requester/spdmd.cpp',
    link_with: spdmd_lib,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)

# Test subdirectory
if get_option('tests').allowed()
    subdir('tests')
endif

# Simple coverage target to satisfy build system
if get_option('coverage')
    custom_target(
        'coverage-html',
        output: 'coverage-html',
        command: ['echo', 'Coverage HTML report would be generated here'],
        build_by_default: false,
    )
endif
