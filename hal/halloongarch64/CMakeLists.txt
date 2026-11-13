# The LoongArch64 HAL. The export catalog is the shared hal.spec, exactly as
# every other architecture uses it; the -arch=loongarch64 entries it carries
# are the private kernel/HAL bridge.
spec2def(hal.dll ../hal.spec ADD_IMPORTLIB)

add_library(hal MODULE
    cache.c
    clock.c
    dma.c
    haldispatch.c
    halinit.c
    halpnpdd.c
    intc.c
    pci.c
    platform.c
    profile.c
    rtc.c
    ../arch/common/generic/secondary.c
    smp.c
    stubs.c
    timer.c
    uart.c
    ${CMAKE_CURRENT_BINARY_DIR}/hal.def)
set_module_type(hal kerneldll ENTRYPOINT 0)
# This HAL is only built for LoongArch64, so it is always the ELF-to-PE link
# path. These catalogue entries live in halcommon archive members that nothing
# else in the HAL references, and ntoskrnl.exe imports HalDisplayString from
# hal.dll, so each one is forced into the link instead of being left out of
# the export directory the spec2def hal.def describes.
target_link_options(hal PRIVATE
    "-Wl,-u,HalAcquireDisplayOwnership"
    "-Wl,-u,HalAllocateHardwareCounters"
    "-Wl,-u,HalBugCheckSystem"
    "-Wl,-u,HalDisableInterrupt"
    "-Wl,-u,HalDisplayString"
    "-Wl,-u,HalEnableInterrupt"
    "-Wl,-u,HalEnumerateEnvironmentVariablesEx"
    "-Wl,-u,HalFreeHardwareCounters"
    "-Wl,-u,HalGetMemoryCachingRequirements"
    "-Wl,-u,HalGetVectorInput"
    "-Wl,-u,HalQueryDisplayParameters"
    "-Wl,-u,HalQueryEnvironmentVariableInfoEx"
    "-Wl,-u,HalSetDisplayParameters"
    "-Wl,-u,HalSystemVectorDispatchEntry")
target_link_libraries(hal halcommon libcntpr)
add_importlibs(hal ntoskrnl)
target_compile_definitions(hal PRIVATE _NTHAL_ _NTHALDLL_)
target_include_directories(hal PRIVATE ${REACTOS_SOURCE_DIR}/ntos/include)
add_dependencies(hal xdk psdk bugcodes)
add_cd_file(TARGET hal DESTINATION reactos/system32 NO_CAB FOR all)
